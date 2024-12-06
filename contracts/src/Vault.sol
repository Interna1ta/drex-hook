// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IERC20} from "@openzeppelin@v5.1.0/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin@v5.1.0/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin@v5.1.0/utils/ReentrancyGuard.sol";
import {ECDSA} from "@openzeppelin@v5.1.0/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin@v5.1.0/utils/cryptography/EIP712.sol";

import {ServiceManager} from "./ServiceManager.sol";

/// @title Vault Contract
/// @notice This contract manages the storage and transfer of assets with attestation and bridge request functionalities.
/// @dev Inherits from Ownable, ReentrancyGuard, and EIP712.
contract Vault is Ownable, ReentrancyGuard, EIP712 {
    using ECDSA for bytes32;

    /* ================== STATE VARS =================== */

    mapping(uint256 => Attestation[]) public s_attestations;
    mapping(uint256 => bool) public s_validBridgeRequests;
    uint256 public s_requiredAttestations;

    mapping(address => uint256) public s_nextUserTransferIndexes;

    uint256 public s_currentBridgeRequestId = 0;
    mapping(uint256 => BridgeRequestData) public s_bridgeRequests;

    uint256 public s_bridgeFee = 0;
    uint256 public s_AVSReward = 0;
    uint256 public s_crankGasCost = 0;
    address public s_canonicalSigner;

    ServiceManager public s_serviceManager;

    /// @notice Structure representing bridge request data
    /// @param user The address of the user initiating the bridge request
    /// @param tokenAddress The address of the token to be bridged
    /// @param amountIn The amount of tokens to be bridged
    /// @param amountOut The amount of tokens expected at the destination
    /// @param destinationVault The address of the destination vault
    /// @param destinationAddress The address of the recipient at the destination
    /// @param transferIndex The transfer index for unique tracking
    struct BridgeRequestData {
        address user;
        address tokenAddress;
        uint256 amountIn;
        uint256 amountOut;
        address destinationVault;
        address destinationAddress;
        uint256 transferIndex;
    }

    /* ==================== EVENTS ==================== */

    event BridgeRequest(
        address indexed user,
        address indexed tokenAddress,
        uint256 indexed bridgeRequestId,
        uint256 amountIn,
        uint256 amountOut,
        address destinationVault,
        address destinationAddress,
        uint256 transferIndex
    );

    event AVSAttestation(
        bytes indexed attestation,
        uint256 indexed bridgeRequestId
    );

    event FundsReleased(
        uint256 indexed bridgeRequestId,
        address destinationAddress,
        uint256 amount
    );

    struct Attestation {
        address operator;
        bytes signature;
    }

    /* ==================== ERRORS ==================== */

    error Vault__IncorrectBridgeFee();
    error Vault__InvalidAVSOperator();
    error Vault__InvalidSignature();
    error Vault__FailedToSendAVSReward();
    error Vault__BridgeRequestNotValidatedByAVS();
    error Vault__InvalidCanonicalSignature();
    error Vault__InvalidDestinationVault();
    error Vault__DataMismatch();
    error Vault__FailedToSendCrankFee();
    error Vault__TransferFailed();

    /* =================== CONSTRUCTOR =================== */

    /// @notice Initializes the Vault contract
    /// @param _serviceManager The address of the ServiceManager contract
    constructor(
        address _serviceManager
    ) Ownable(msg.sender) EIP712("Jurassic", "1") {
        s_serviceManager = ServiceManager(_serviceManager);

        s_canonicalSigner = msg.sender;
    }

    /* ==================== EXTERNAL ==================== */

    /// @notice Sets the required number of attestations for a bridge request to be considered valid
    /// @dev Only the owner can call this function
    /// @param _requiredAttestations The number of required attestations
    function setRequiredAttestations(
        uint256 _requiredAttestations
    ) external onlyOwner {
        s_requiredAttestations = _requiredAttestations;
    }

    /// @notice Sets the canonical signer address
    /// @dev Only the owner can call this function
    /// @param _canonicalSigner The address of the canonical signer
    function setCanonicalSigner(address _canonicalSigner) external onlyOwner {
        s_canonicalSigner = _canonicalSigner;
    }

    /// @notice Sets the bridge fee
    /// @dev Only the owner can call this function
    /// @param _bridgeFee The bridge fee in wei
    function setBridgeFee(uint256 _bridgeFee) external onlyOwner {
        s_bridgeFee = _bridgeFee;
    }

    /// @notice Sets the AVS reward
    /// @dev Only the owner can call this function
    /// @param _AVSReward The AVS reward in wei
    function setAVSReward(uint256 _AVSReward) external onlyOwner {
        s_AVSReward = _AVSReward;
    }

    /// @notice Sets the crank gas cost
    /// @dev Only the owner can call this function
    /// @param _crankGasCost The crank gas cost in wei
    function setCrankGasCost(uint256 _crankGasCost) external onlyOwner {
        s_crankGasCost = _crankGasCost;
    }

    /* ==================== PUBLIC ==================== */

    /// @notice Returns the digest of the bridge request data
    /// @param _data The bridge request data
    /// @return The digest of the bridge request data
    function getDigest(
        BridgeRequestData memory _data
    ) public view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        keccak256(
                            "BridgeRequestData(address user,address tokenAddress,uint256 amountIn,uint256 amountOut,address destinationVault,address destinationAddress,uint256 transferIndex)"
                        ),
                        _data.user,
                        _data.tokenAddress,
                        _data.amountIn,
                        _data.amountOut,
                        _data.destinationVault,
                        _data.destinationAddress,
                        _data.transferIndex
                    )
                )
            );
    }

    /// @notice Returns the signer of the bridge request data
    /// @param _data The bridge request data
    /// @param _signature The signature of the bridge request data
    /// @return The address of the signer
    function getSigner(
        BridgeRequestData memory _data,
        bytes memory _signature
    ) public view returns (address) {
        bytes32 digest = getDigest(_data);
        return ECDSA.recover(digest, _signature);
    }

    /// @notice Initiates a bridge request
    /// @param _tokenAddress The address of the token to be bridged
    /// @param _amountIn The amount of tokens to be bridged
    /// @param _amountOut The amount of tokens to be received on the destination chain
    /// @param _destinationVault The address of the destination vault
    /// @param _destinationAddress The address of the recipient on the destination chain
    function bridge(
        address _tokenAddress,
        uint256 _amountIn,
        uint256 _amountOut,
        address _destinationVault,
        address _destinationAddress
    ) public payable nonReentrant {
        require(msg.value == s_bridgeFee, Vault__IncorrectBridgeFee());

        bridgeERC20(_tokenAddress, _amountIn);
        uint256 transferIndex = s_nextUserTransferIndexes[msg.sender];

        emit BridgeRequest(
            msg.sender,
            _tokenAddress,
            s_currentBridgeRequestId,
            _amountIn,
            _amountOut,
            _destinationVault,
            _destinationAddress,
            transferIndex
        );

        s_bridgeRequests[s_currentBridgeRequestId] = BridgeRequestData(
            msg.sender,
            _tokenAddress,
            _amountIn,
            _amountOut,
            _destinationVault,
            _destinationAddress,
            transferIndex
        );

        s_currentBridgeRequestId++;
        s_nextUserTransferIndexes[msg.sender]++;

        validateBridgeRequest(
            msg.sender,
            _tokenAddress,
            _amountIn,
            _amountOut,
            _destinationVault,
            _destinationAddress,
            transferIndex,
            s_currentBridgeRequestId
        );
    }

    /// @notice Publishes an attestation for a bridge request
    /// @param _bridgeRequestId The ID of the bridge request
    /// @param _signature The signature of the attestation
    function publishAttestation(
        uint256 _bridgeRequestId,
        bytes memory _signature
    ) external nonReentrant {
        require(
            s_serviceManager.isActiveOperator(msg.sender),
            Vault__InvalidAVSOperator()
        );

        BridgeRequestData memory request = s_bridgeRequests[_bridgeRequestId];

        // Verify the operator's _

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                _bridgeRequestId,
                request.user,
                request.tokenAddress,
                request.amountIn,
                request.amountOut,
                request.destinationVault,
                request.destinationAddress,
                request.transferIndex
            )
        );
        require(
            ECDSA.recover(messageHash, _signature) == msg.sender,
            Vault__InvalidSignature()
        );

        // Store the attestation

        s_attestations[_bridgeRequestId].push(
            Attestation(msg.sender, _signature)
        );

        emit AVSAttestation(_signature, _bridgeRequestId);

        // If we have enough attestations, mark the bridge request as valid
        if (s_attestations[_bridgeRequestId].length >= s_requiredAttestations) {
            s_validBridgeRequests[_bridgeRequestId] = true;
        }

        // Pay the operator

        uint256 payout = s_AVSReward;
        if (address(this).balance < payout) {
            payout = address(this).balance;
        }

        (bool sent, ) = msg.sender.call{value: payout}("");
        require(sent, Vault__FailedToSendAVSReward());
    }

    /// @notice Releases funds for a validated bridge request
    /// @param _canonicalSignature The canonical signature of the bridge request
    /// @param _data The bridge request data
    function releaseFunds(
        bytes memory _canonicalSignature,
        BridgeRequestData memory _data
    ) public nonReentrant {
        uint256 bridgeRequestId = getBridgeRequestId(_data);
        require(
            s_validBridgeRequests[bridgeRequestId],
            Vault__BridgeRequestNotValidatedByAVS()
        );

        // Verify canonical signer's signature

        require(
            getSigner(_data, _canonicalSignature) == s_canonicalSigner,
            Vault__InvalidCanonicalSignature()
        );

        require(
            _data.destinationVault == address(this),
            Vault__InvalidDestinationVault()
        );

        // Verify that the provided data matches the stored bridge request

        BridgeRequestData memory storedData = s_bridgeRequests[bridgeRequestId];
        require(
            keccak256(abi.encode(_data)) == keccak256(abi.encode(storedData)),
            Vault__DataMismatch()
        );

        IERC20(_data.tokenAddress).approve(address(this), _data.amountOut);
        IERC20(_data.tokenAddress).transfer(
            _data.destinationAddress,
            _data.amountOut
        );

        uint256 payout = s_crankGasCost * tx.gasprice;
        if (address(this).balance < payout) {
            payout = address(this).balance;
        }

        if (payout > 0) {
            (bool sent, ) = msg.sender.call{value: payout}("");
            require(sent, Vault__FailedToSendCrankFee());
        }

        // Mark the bridge request as processed to prevent double-spending

        delete s_validBridgeRequests[bridgeRequestId];
        delete s_bridgeRequests[bridgeRequestId];

        emit FundsReleased(
            bridgeRequestId,
            _data.destinationAddress,
            _data.amountOut
        );
    }

    /// @notice Returns the bridge request ID for the given bridge request data
    /// @param _data The bridge request data
    /// @return The bridge request ID
    function getBridgeRequestId(
        BridgeRequestData memory _data
    ) public pure returns (uint256) {
        return
            uint256(
                keccak256(
                    abi.encode(
                        _data.user,
                        _data.tokenAddress,
                        _data.amountIn,
                        _data.amountOut,
                        _data.destinationVault,
                        _data.destinationAddress,
                        _data.transferIndex
                    )
                )
            );
    }

    /* ==================== INTERNAL ==================== */

    /// @notice Transfers ERC20 tokens from the sender to the contract
    /// @param _tokenAddress The address of the token to be transferred
    /// @param _amountIn The amount of tokens to be transferred
    function bridgeERC20(address _tokenAddress, uint256 _amountIn) internal {
        bool success = IERC20(_tokenAddress).transferFrom(
            msg.sender,
            address(this),
            _amountIn
        );
        require(success, Vault__TransferFailed());
    }

    /// @notice Validates a bridge request
    /// @param _user The address of the user initiating the bridge request
    /// @param _tokenAddress The address of the token to be bridged
    /// @param _amountIn The amount of tokens to be bridged
    /// @param _amountOut The amount of tokens to be received on the destination chain
    /// @param _destinationVault The address of the destination vault
    /// @param _destinationAddress The address of the recipient on the destination chain
    /// @param _transferIndex The transfer index
    /// @param _bridgeRequestId The ID of the bridge request
    /// @return isValid A boolean indicating whether the bridge request is valid
    function validateBridgeRequest(
        address _user,
        address _tokenAddress,
        uint256 _amountIn,
        uint256 _amountOut,
        address _destinationVault,
        address _destinationAddress,
        uint256 _transferIndex,
        uint256 _bridgeRequestId
    ) internal view returns (bool isValid) {
        // Check if the bridge request exists and matches the provided data

        BridgeRequestData memory request = s_bridgeRequests[_bridgeRequestId];
        require(request.user == _user, "User mismatch");
        require(request.tokenAddress == _tokenAddress, "Token mismatch");
        require(request.amountIn == _amountIn, "Amount in mismatch");
        require(request.amountOut == _amountOut, "Amount out mismatch");
        require(
            request.destinationVault == _destinationVault,
            "Destination vault mismatch"
        );
        require(
            request.destinationAddress == _destinationAddress,
            "Destination address mismatch"
        );
        require(
            request.transferIndex == _transferIndex,
            "Transfer index mismatch"
        );

        // Some more additional checks

        require(_amountIn > 0 && _amountOut > 0, "Invalid amounts");
        require(
            _user != address(0) && _destinationAddress != address(0),
            "Invalid addresses"
        );

        // Check if the user has sufficient balance

        IERC20 token = IERC20(_tokenAddress);
        require(token.balanceOf(_user) >= _amountIn, "Insufficient balance");

        // Perhaps we check if the destination vault is whitelisted?
        // require(isWhitelistedVault(destinationVault), "Invalid destination vault");

        return true;
    }

    receive() external payable {}
}
