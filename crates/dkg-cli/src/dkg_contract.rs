pub use dkg_mod::*;
#[allow(clippy::too_many_arguments)]
mod dkg_mod {
    #![allow(clippy::enum_variant_names)]
    #![allow(dead_code)]
    #![allow(clippy::type_complexity)]
    #![allow(unused_imports)]
    use ethers::contract::{
        builders::{ContractCall, Event},
        Contract, Lazy,
    };
    use ethers::core::{
        abi::{Abi, Detokenize, InvalidOutputType, Token, Tokenizable},
        types::*,
    };
    use ethers::providers::Middleware;
    #[doc = "DKG was auto-generated with ethers-rs Abigen. More information at: https://github.com/gakonst/ethers-rs"]
    use std::sync::Arc;
    pub static DKG_ABI: ethers::contract::Lazy<ethers::core::abi::Abi> =
        ethers::contract::Lazy::new(|| {
            serde_json :: from_str ("[{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"threshold\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"duration\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"inputs\":[],\"name\":\"PHASE_DURATION\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"THRESHOLD\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"}],\"name\":\"allowlist\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getBlsKeys\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"},{\"internalType\":\"bytes[]\",\"name\":\"\",\"type\":\"bytes[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getJustifications\",\"outputs\":[{\"internalType\":\"bytes[]\",\"name\":\"\",\"type\":\"bytes[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getParticipants\",\"outputs\":[{\"internalType\":\"address[]\",\"name\":\"\",\"type\":\"address[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getResponses\",\"outputs\":[{\"internalType\":\"bytes[]\",\"name\":\"\",\"type\":\"bytes[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getShares\",\"outputs\":[{\"internalType\":\"bytes[]\",\"name\":\"\",\"type\":\"bytes[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"inPhase\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"justifications\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"keys\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"owner\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"participants\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"value\",\"type\":\"bytes\"}],\"name\":\"publish\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"blsPublicKey\",\"type\":\"bytes\"}],\"name\":\"register\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"responses\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"shares\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"start\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"startBlock\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"userState\",\"outputs\":[{\"internalType\":\"enum DKG.UserState\",\"name\":\"\",\"type\":\"uint8\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]") . expect ("invalid abi")
        });
    #[derive(Clone)]
    pub struct DKG<M>(ethers::contract::Contract<M>);
    impl<M> std::ops::Deref for DKG<M> {
        type Target = ethers::contract::Contract<M>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl<M: ethers::providers::Middleware> std::fmt::Debug for DKG<M> {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.debug_tuple(stringify!(DKG))
                .field(&self.address())
                .finish()
        }
    }
    impl<'a, M: ethers::providers::Middleware> DKG<M> {
        #[doc = r" Creates a new contract instance with the specified `ethers`"]
        #[doc = r" client at the given `Address`. The contract derefs to a `ethers::Contract`"]
        #[doc = r" object"]
        pub fn new<T: Into<ethers::core::types::Address>>(
            address: T,
            client: ::std::sync::Arc<M>,
        ) -> Self {
            let contract = ethers::contract::Contract::new(address.into(), DKG_ABI.clone(), client);
            Self(contract)
        }
        #[doc = "Calls the contract's `PHASE_DURATION` (0x4ae2b849) function"]
        pub fn phase_duration(
            &self,
        ) -> ethers::contract::builders::ContractCall<M, ethers::core::types::U256> {
            self.0
                .method_hash([74, 226, 184, 73], ())
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `THRESHOLD` (0x785ffb37) function"]
        pub fn threshold(
            &self,
        ) -> ethers::contract::builders::ContractCall<M, ethers::core::types::U256> {
            self.0
                .method_hash([120, 95, 251, 55], ())
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `allowlist` (0xa7cd52cb) function"]
        pub fn allowlist(
            &self,
            user: ethers::core::types::Address,
        ) -> ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([167, 205, 82, 203], user)
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `getBlsKeys` (0xa8194596) function"]
        pub fn get_bls_keys(
            &self,
        ) -> ethers::contract::builders::ContractCall<
            M,
            (
                ethers::core::types::U256,
                ::std::vec::Vec<ethers::core::types::Bytes>,
            ),
        > {
            self.0
                .method_hash([168, 25, 69, 150], ())
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `getJustifications` (0xb0ef8179) function"]
        pub fn get_justifications(
            &self,
        ) -> ethers::contract::builders::ContractCall<M, ::std::vec::Vec<ethers::core::types::Bytes>>
        {
            self.0
                .method_hash([176, 239, 129, 121], ())
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `getParticipants` (0x5aa68ac0) function"]
        pub fn get_participants(
            &self,
        ) -> ethers::contract::builders::ContractCall<
            M,
            ::std::vec::Vec<ethers::core::types::Address>,
        > {
            self.0
                .method_hash([90, 166, 138, 192], ())
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `getResponses` (0xcc5ef009) function"]
        pub fn get_responses(
            &self,
        ) -> ethers::contract::builders::ContractCall<M, ::std::vec::Vec<ethers::core::types::Bytes>>
        {
            self.0
                .method_hash([204, 94, 240, 9], ())
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `getShares` (0xd73fe0aa) function"]
        pub fn get_shares(
            &self,
        ) -> ethers::contract::builders::ContractCall<M, ::std::vec::Vec<ethers::core::types::Bytes>>
        {
            self.0
                .method_hash([215, 63, 224, 170], ())
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `inPhase` (0x221f9511) function"]
        pub fn in_phase(
            &self,
        ) -> ethers::contract::builders::ContractCall<M, ethers::core::types::U256> {
            self.0
                .method_hash([34, 31, 149, 17], ())
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `justifications` (0xcd5e3837) function"]
        pub fn justifications(
            &self,
            p0: ethers::core::types::Address,
        ) -> ethers::contract::builders::ContractCall<M, ethers::core::types::Bytes> {
            self.0
                .method_hash([205, 94, 56, 55], p0)
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `keys` (0x670d14b2) function"]
        pub fn keys(
            &self,
            p0: ethers::core::types::Address,
        ) -> ethers::contract::builders::ContractCall<M, ethers::core::types::Bytes> {
            self.0
                .method_hash([103, 13, 20, 178], p0)
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `owner` (0x8da5cb5b) function"]
        pub fn owner(
            &self,
        ) -> ethers::contract::builders::ContractCall<M, ethers::core::types::Address> {
            self.0
                .method_hash([141, 165, 203, 91], ())
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `participants` (0x35c1d349) function"]
        pub fn participants(
            &self,
            p0: ethers::core::types::U256,
        ) -> ethers::contract::builders::ContractCall<M, ethers::core::types::Address> {
            self.0
                .method_hash([53, 193, 211, 73], p0)
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `publish` (0x7fd28346) function"]
        pub fn publish(
            &self,
            value: ethers::core::types::Bytes,
        ) -> ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([127, 210, 131, 70], value)
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `register` (0x82fbdc9c) function"]
        pub fn register(
            &self,
            bls_public_key: ethers::core::types::Bytes,
        ) -> ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([130, 251, 220, 156], bls_public_key)
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `responses` (0x0ea65648) function"]
        pub fn responses(
            &self,
            p0: ethers::core::types::Address,
        ) -> ethers::contract::builders::ContractCall<M, ethers::core::types::Bytes> {
            self.0
                .method_hash([14, 166, 86, 72], p0)
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `shares` (0xce7c2ac2) function"]
        pub fn shares(
            &self,
            p0: ethers::core::types::Address,
        ) -> ethers::contract::builders::ContractCall<M, ethers::core::types::Bytes> {
            self.0
                .method_hash([206, 124, 42, 194], p0)
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `start` (0xbe9a6555) function"]
        pub fn start(&self) -> ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([190, 154, 101, 85], ())
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `startBlock` (0x48cd4cb1) function"]
        pub fn start_block(
            &self,
        ) -> ethers::contract::builders::ContractCall<M, ethers::core::types::U256> {
            self.0
                .method_hash([72, 205, 76, 177], ())
                .expect("method not found (this should never happen)")
        }
        #[doc = "Calls the contract's `userState` (0x0c8f81b5) function"]
        pub fn user_state(
            &self,
            p0: ethers::core::types::Address,
        ) -> ethers::contract::builders::ContractCall<M, u8> {
            self.0
                .method_hash([12, 143, 129, 181], p0)
                .expect("method not found (this should never happen)")
        }
    }
    #[doc = "Container type for all input parameters for the `PHASE_DURATION`function with signature `PHASE_DURATION()` and selector `[74, 226, 184, 73]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "PHASE_DURATION", abi = "PHASE_DURATION()")]
    pub struct PhaseDurationCall;
    #[doc = "Container type for all input parameters for the `THRESHOLD`function with signature `THRESHOLD()` and selector `[120, 95, 251, 55]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "THRESHOLD", abi = "THRESHOLD()")]
    pub struct ThresholdCall;
    #[doc = "Container type for all input parameters for the `allowlist`function with signature `allowlist(address)` and selector `[167, 205, 82, 203]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "allowlist", abi = "allowlist(address)")]
    pub struct AllowlistCall {
        pub user: ethers::core::types::Address,
    }
    #[doc = "Container type for all input parameters for the `getBlsKeys`function with signature `getBlsKeys()` and selector `[168, 25, 69, 150]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "getBlsKeys", abi = "getBlsKeys()")]
    pub struct GetBlsKeysCall;
    #[doc = "Container type for all input parameters for the `getJustifications`function with signature `getJustifications()` and selector `[176, 239, 129, 121]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "getJustifications", abi = "getJustifications()")]
    pub struct GetJustificationsCall;
    #[doc = "Container type for all input parameters for the `getParticipants`function with signature `getParticipants()` and selector `[90, 166, 138, 192]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "getParticipants", abi = "getParticipants()")]
    pub struct GetParticipantsCall;
    #[doc = "Container type for all input parameters for the `getResponses`function with signature `getResponses()` and selector `[204, 94, 240, 9]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "getResponses", abi = "getResponses()")]
    pub struct GetResponsesCall;
    #[doc = "Container type for all input parameters for the `getShares`function with signature `getShares()` and selector `[215, 63, 224, 170]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "getShares", abi = "getShares()")]
    pub struct GetSharesCall;
    #[doc = "Container type for all input parameters for the `inPhase`function with signature `inPhase()` and selector `[34, 31, 149, 17]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "inPhase", abi = "inPhase()")]
    pub struct InPhaseCall;
    #[doc = "Container type for all input parameters for the `justifications`function with signature `justifications(address)` and selector `[205, 94, 56, 55]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "justifications", abi = "justifications(address)")]
    pub struct JustificationsCall(pub ethers::core::types::Address);
    #[doc = "Container type for all input parameters for the `keys`function with signature `keys(address)` and selector `[103, 13, 20, 178]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "keys", abi = "keys(address)")]
    pub struct KeysCall(pub ethers::core::types::Address);
    #[doc = "Container type for all input parameters for the `owner`function with signature `owner()` and selector `[141, 165, 203, 91]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "owner", abi = "owner()")]
    pub struct OwnerCall;
    #[doc = "Container type for all input parameters for the `participants`function with signature `participants(uint256)` and selector `[53, 193, 211, 73]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "participants", abi = "participants(uint256)")]
    pub struct ParticipantsCall(pub ethers::core::types::U256);
    #[doc = "Container type for all input parameters for the `publish`function with signature `publish(bytes)` and selector `[127, 210, 131, 70]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "publish", abi = "publish(bytes)")]
    pub struct PublishCall {
        pub value: ethers::core::types::Bytes,
    }
    #[doc = "Container type for all input parameters for the `register`function with signature `register(bytes)` and selector `[130, 251, 220, 156]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "register", abi = "register(bytes)")]
    pub struct RegisterCall {
        pub bls_public_key: ethers::core::types::Bytes,
    }
    #[doc = "Container type for all input parameters for the `responses`function with signature `responses(address)` and selector `[14, 166, 86, 72]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "responses", abi = "responses(address)")]
    pub struct ResponsesCall(pub ethers::core::types::Address);
    #[doc = "Container type for all input parameters for the `shares`function with signature `shares(address)` and selector `[206, 124, 42, 194]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "shares", abi = "shares(address)")]
    pub struct SharesCall(pub ethers::core::types::Address);
    #[doc = "Container type for all input parameters for the `start`function with signature `start()` and selector `[190, 154, 101, 85]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "start", abi = "start()")]
    pub struct StartCall;
    #[doc = "Container type for all input parameters for the `startBlock`function with signature `startBlock()` and selector `[72, 205, 76, 177]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "startBlock", abi = "startBlock()")]
    pub struct StartBlockCall;
    #[doc = "Container type for all input parameters for the `userState`function with signature `userState(address)` and selector `[12, 143, 129, 181]`"]
    #[derive(
        Clone,
        Debug,
        Default,
        Eq,
        PartialEq,
        ethers :: contract :: EthCall,
        ethers :: contract :: EthDisplay,
    )]
    #[ethcall(name = "userState", abi = "userState(address)")]
    pub struct UserStateCall(pub ethers::core::types::Address);
    #[derive(Debug, Clone, PartialEq, Eq, ethers :: contract :: EthAbiType)]
    pub enum DKGCalls {
        PhaseDuration(PhaseDurationCall),
        Threshold(ThresholdCall),
        Allowlist(AllowlistCall),
        GetBlsKeys(GetBlsKeysCall),
        GetJustifications(GetJustificationsCall),
        GetParticipants(GetParticipantsCall),
        GetResponses(GetResponsesCall),
        GetShares(GetSharesCall),
        InPhase(InPhaseCall),
        Justifications(JustificationsCall),
        Keys(KeysCall),
        Owner(OwnerCall),
        Participants(ParticipantsCall),
        Publish(PublishCall),
        Register(RegisterCall),
        Responses(ResponsesCall),
        Shares(SharesCall),
        Start(StartCall),
        StartBlock(StartBlockCall),
        UserState(UserStateCall),
    }
    impl ethers::core::abi::AbiDecode for DKGCalls {
        fn decode(data: impl AsRef<[u8]>) -> Result<Self, ethers::core::abi::AbiError> {
            if let Ok(decoded) =
                <PhaseDurationCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::PhaseDuration(decoded));
            }
            if let Ok(decoded) =
                <ThresholdCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::Threshold(decoded));
            }
            if let Ok(decoded) =
                <AllowlistCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::Allowlist(decoded));
            }
            if let Ok(decoded) =
                <GetBlsKeysCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::GetBlsKeys(decoded));
            }
            if let Ok(decoded) =
                <GetJustificationsCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::GetJustifications(decoded));
            }
            if let Ok(decoded) =
                <GetParticipantsCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::GetParticipants(decoded));
            }
            if let Ok(decoded) =
                <GetResponsesCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::GetResponses(decoded));
            }
            if let Ok(decoded) =
                <GetSharesCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::GetShares(decoded));
            }
            if let Ok(decoded) =
                <InPhaseCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::InPhase(decoded));
            }
            if let Ok(decoded) =
                <JustificationsCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::Justifications(decoded));
            }
            if let Ok(decoded) = <KeysCall as ethers::core::abi::AbiDecode>::decode(data.as_ref()) {
                return Ok(DKGCalls::Keys(decoded));
            }
            if let Ok(decoded) = <OwnerCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::Owner(decoded));
            }
            if let Ok(decoded) =
                <ParticipantsCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::Participants(decoded));
            }
            if let Ok(decoded) =
                <PublishCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::Publish(decoded));
            }
            if let Ok(decoded) =
                <RegisterCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::Register(decoded));
            }
            if let Ok(decoded) =
                <ResponsesCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::Responses(decoded));
            }
            if let Ok(decoded) = <SharesCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::Shares(decoded));
            }
            if let Ok(decoded) = <StartCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::Start(decoded));
            }
            if let Ok(decoded) =
                <StartBlockCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::StartBlock(decoded));
            }
            if let Ok(decoded) =
                <UserStateCall as ethers::core::abi::AbiDecode>::decode(data.as_ref())
            {
                return Ok(DKGCalls::UserState(decoded));
            }
            Err(ethers::core::abi::Error::InvalidData.into())
        }
    }
    impl ethers::core::abi::AbiEncode for DKGCalls {
        fn encode(self) -> Vec<u8> {
            match self {
                DKGCalls::PhaseDuration(element) => element.encode(),
                DKGCalls::Threshold(element) => element.encode(),
                DKGCalls::Allowlist(element) => element.encode(),
                DKGCalls::GetBlsKeys(element) => element.encode(),
                DKGCalls::GetJustifications(element) => element.encode(),
                DKGCalls::GetParticipants(element) => element.encode(),
                DKGCalls::GetResponses(element) => element.encode(),
                DKGCalls::GetShares(element) => element.encode(),
                DKGCalls::InPhase(element) => element.encode(),
                DKGCalls::Justifications(element) => element.encode(),
                DKGCalls::Keys(element) => element.encode(),
                DKGCalls::Owner(element) => element.encode(),
                DKGCalls::Participants(element) => element.encode(),
                DKGCalls::Publish(element) => element.encode(),
                DKGCalls::Register(element) => element.encode(),
                DKGCalls::Responses(element) => element.encode(),
                DKGCalls::Shares(element) => element.encode(),
                DKGCalls::Start(element) => element.encode(),
                DKGCalls::StartBlock(element) => element.encode(),
                DKGCalls::UserState(element) => element.encode(),
            }
        }
    }
    impl ::std::fmt::Display for DKGCalls {
        fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
            match self {
                DKGCalls::PhaseDuration(element) => element.fmt(f),
                DKGCalls::Threshold(element) => element.fmt(f),
                DKGCalls::Allowlist(element) => element.fmt(f),
                DKGCalls::GetBlsKeys(element) => element.fmt(f),
                DKGCalls::GetJustifications(element) => element.fmt(f),
                DKGCalls::GetParticipants(element) => element.fmt(f),
                DKGCalls::GetResponses(element) => element.fmt(f),
                DKGCalls::GetShares(element) => element.fmt(f),
                DKGCalls::InPhase(element) => element.fmt(f),
                DKGCalls::Justifications(element) => element.fmt(f),
                DKGCalls::Keys(element) => element.fmt(f),
                DKGCalls::Owner(element) => element.fmt(f),
                DKGCalls::Participants(element) => element.fmt(f),
                DKGCalls::Publish(element) => element.fmt(f),
                DKGCalls::Register(element) => element.fmt(f),
                DKGCalls::Responses(element) => element.fmt(f),
                DKGCalls::Shares(element) => element.fmt(f),
                DKGCalls::Start(element) => element.fmt(f),
                DKGCalls::StartBlock(element) => element.fmt(f),
                DKGCalls::UserState(element) => element.fmt(f),
            }
        }
    }
    impl ::std::convert::From<PhaseDurationCall> for DKGCalls {
        fn from(var: PhaseDurationCall) -> Self {
            DKGCalls::PhaseDuration(var)
        }
    }
    impl ::std::convert::From<ThresholdCall> for DKGCalls {
        fn from(var: ThresholdCall) -> Self {
            DKGCalls::Threshold(var)
        }
    }
    impl ::std::convert::From<AllowlistCall> for DKGCalls {
        fn from(var: AllowlistCall) -> Self {
            DKGCalls::Allowlist(var)
        }
    }
    impl ::std::convert::From<GetBlsKeysCall> for DKGCalls {
        fn from(var: GetBlsKeysCall) -> Self {
            DKGCalls::GetBlsKeys(var)
        }
    }
    impl ::std::convert::From<GetJustificationsCall> for DKGCalls {
        fn from(var: GetJustificationsCall) -> Self {
            DKGCalls::GetJustifications(var)
        }
    }
    impl ::std::convert::From<GetParticipantsCall> for DKGCalls {
        fn from(var: GetParticipantsCall) -> Self {
            DKGCalls::GetParticipants(var)
        }
    }
    impl ::std::convert::From<GetResponsesCall> for DKGCalls {
        fn from(var: GetResponsesCall) -> Self {
            DKGCalls::GetResponses(var)
        }
    }
    impl ::std::convert::From<GetSharesCall> for DKGCalls {
        fn from(var: GetSharesCall) -> Self {
            DKGCalls::GetShares(var)
        }
    }
    impl ::std::convert::From<InPhaseCall> for DKGCalls {
        fn from(var: InPhaseCall) -> Self {
            DKGCalls::InPhase(var)
        }
    }
    impl ::std::convert::From<JustificationsCall> for DKGCalls {
        fn from(var: JustificationsCall) -> Self {
            DKGCalls::Justifications(var)
        }
    }
    impl ::std::convert::From<KeysCall> for DKGCalls {
        fn from(var: KeysCall) -> Self {
            DKGCalls::Keys(var)
        }
    }
    impl ::std::convert::From<OwnerCall> for DKGCalls {
        fn from(var: OwnerCall) -> Self {
            DKGCalls::Owner(var)
        }
    }
    impl ::std::convert::From<ParticipantsCall> for DKGCalls {
        fn from(var: ParticipantsCall) -> Self {
            DKGCalls::Participants(var)
        }
    }
    impl ::std::convert::From<PublishCall> for DKGCalls {
        fn from(var: PublishCall) -> Self {
            DKGCalls::Publish(var)
        }
    }
    impl ::std::convert::From<RegisterCall> for DKGCalls {
        fn from(var: RegisterCall) -> Self {
            DKGCalls::Register(var)
        }
    }
    impl ::std::convert::From<ResponsesCall> for DKGCalls {
        fn from(var: ResponsesCall) -> Self {
            DKGCalls::Responses(var)
        }
    }
    impl ::std::convert::From<SharesCall> for DKGCalls {
        fn from(var: SharesCall) -> Self {
            DKGCalls::Shares(var)
        }
    }
    impl ::std::convert::From<StartCall> for DKGCalls {
        fn from(var: StartCall) -> Self {
            DKGCalls::Start(var)
        }
    }
    impl ::std::convert::From<StartBlockCall> for DKGCalls {
        fn from(var: StartBlockCall) -> Self {
            DKGCalls::StartBlock(var)
        }
    }
    impl ::std::convert::From<UserStateCall> for DKGCalls {
        fn from(var: UserStateCall) -> Self {
            DKGCalls::UserState(var)
        }
    }
}
