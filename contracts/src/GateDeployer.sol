// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {GateProxy} from "./GateProxy.sol";
import {Gate} from "./Gate.sol";

/// @title GateDeployer
/// @notice The one place that knows how to stand a {Gate} up behind its proxy.
/// @dev    Deploying a UUPS gate is a two-step dance with a sharp edge: the
///         implementation must never be initialized, and the proxy must be
///         initialized in the SAME transaction that creates it. A proxy left
///         uninitialized for even one block can be initialized by anyone, and
///         whoever does that becomes `owner` of a gate users may already have
///         sent funds to. Passing the `initialize` calldata to the ERC1967Proxy
///         constructor closes that window atomically, which is why every caller
///         — scripts and tests alike — goes through here instead of hand-rolling
///         `new Gate()` + `new ERC1967Proxy()`.
///
///         `internal`, so it inlines into the caller. That matters: `msg.sender`
///         inside `initialize` is whoever calls this, so the deploying
///         script/contract becomes the gate's `owner` exactly as it did when
///         Gate still had a real constructor.
library GateDeployer {
    /// @return gate the PROXY address. This is the bridge gate — the address that
    ///         belongs in every chain config, validator source and keeper target.
    ///         The implementation address is an internal detail that changes on
    ///         every upgrade and must never be configured anywhere.
    /// @dev    The gate comes back UNSEALED with an empty destination registry:
    ///         `send` refuses every chain until the owner lists it with
    ///         {Gate.setSupportedChain}, and {Gate.setLocalToken} is instant until
    ///         the owner calls {Gate.seal}. Wire chains and corridors, then seal,
    ///         then fund — see {Gate.isSealed} for why that order matters.
    function deploy(address[] memory validators, uint256 threshold, bytes32 bridgeDomain)
        internal
        returns (Gate gate)
    {
        Gate implementation = new Gate();
        GateProxy proxy = new GateProxy(
            address(implementation),
            abi.encodeCall(Gate.initialize, (validators, threshold, bridgeDomain))
        );
        return Gate(address(proxy));
    }
}
