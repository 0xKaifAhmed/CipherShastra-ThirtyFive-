/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import {
  ethers,
  EventFilter,
  Signer,
  BigNumber,
  BigNumberish,
  PopulatedTransaction,
  BaseContract,
  ContractTransaction,
  Overrides,
  CallOverrides,
} from "ethers";
import { BytesLike } from "@ethersproject/bytes";
import { Listener, Provider } from "@ethersproject/providers";
import { FunctionFragment, EventFragment, Result } from "@ethersproject/abi";
import type { TypedEventFilter, TypedEvent, TypedListener } from "./common";

interface ThirtyFiveInterface extends ethers.utils.Interface {
  functions: {
    "DOMAIN_SEPARATOR()": FunctionFragment;
    "DOMAIN_TYPEHASH()": FunctionFragment;
    "HackerWho()": FunctionFragment;
    "SIGNING_TYPEHASH()": FunctionFragment;
    "giveMeMyToken()": FunctionFragment;
    "name()": FunctionFragment;
    "nonces(address)": FunctionFragment;
    "pwn(bytes32)": FunctionFragment;
    "pwnCounter(address)": FunctionFragment;
    "signItLikeYouMeanIt(uint16,uint256,bytes)": FunctionFragment;
    "version()": FunctionFragment;
  };

  encodeFunctionData(
    functionFragment: "DOMAIN_SEPARATOR",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "DOMAIN_TYPEHASH",
    values?: undefined
  ): string;
  encodeFunctionData(functionFragment: "HackerWho", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "SIGNING_TYPEHASH",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "giveMeMyToken",
    values?: undefined
  ): string;
  encodeFunctionData(functionFragment: "name", values?: undefined): string;
  encodeFunctionData(functionFragment: "nonces", values: [string]): string;
  encodeFunctionData(functionFragment: "pwn", values: [BytesLike]): string;
  encodeFunctionData(functionFragment: "pwnCounter", values: [string]): string;
  encodeFunctionData(
    functionFragment: "signItLikeYouMeanIt",
    values: [BigNumberish, BigNumberish, BytesLike]
  ): string;
  encodeFunctionData(functionFragment: "version", values?: undefined): string;

  decodeFunctionResult(
    functionFragment: "DOMAIN_SEPARATOR",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "DOMAIN_TYPEHASH",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "HackerWho", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "SIGNING_TYPEHASH",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "giveMeMyToken",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "name", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "nonces", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "pwn", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "pwnCounter", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "signItLikeYouMeanIt",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "version", data: BytesLike): Result;

  events: {
    "TokenGen(address,bytes32)": EventFragment;
  };

  getEvent(nameOrSignatureOrTopic: "TokenGen"): EventFragment;
}

export type TokenGenEvent = TypedEvent<
  [string, string] & { signer: string; token: string }
>;

export class ThirtyFive extends BaseContract {
  connect(signerOrProvider: Signer | Provider | string): this;
  attach(addressOrName: string): this;
  deployed(): Promise<this>;

  listeners<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter?: TypedEventFilter<EventArgsArray, EventArgsObject>
  ): Array<TypedListener<EventArgsArray, EventArgsObject>>;
  off<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>,
    listener: TypedListener<EventArgsArray, EventArgsObject>
  ): this;
  on<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>,
    listener: TypedListener<EventArgsArray, EventArgsObject>
  ): this;
  once<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>,
    listener: TypedListener<EventArgsArray, EventArgsObject>
  ): this;
  removeListener<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>,
    listener: TypedListener<EventArgsArray, EventArgsObject>
  ): this;
  removeAllListeners<EventArgsArray extends Array<any>, EventArgsObject>(
    eventFilter: TypedEventFilter<EventArgsArray, EventArgsObject>
  ): this;

  listeners(eventName?: string): Array<Listener>;
  off(eventName: string, listener: Listener): this;
  on(eventName: string, listener: Listener): this;
  once(eventName: string, listener: Listener): this;
  removeListener(eventName: string, listener: Listener): this;
  removeAllListeners(eventName?: string): this;

  queryFilter<EventArgsArray extends Array<any>, EventArgsObject>(
    event: TypedEventFilter<EventArgsArray, EventArgsObject>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TypedEvent<EventArgsArray & EventArgsObject>>>;

  interface: ThirtyFiveInterface;

  functions: {
    DOMAIN_SEPARATOR(overrides?: CallOverrides): Promise<[string]>;

    DOMAIN_TYPEHASH(overrides?: CallOverrides): Promise<[string]>;

    HackerWho(overrides?: CallOverrides): Promise<[string]>;

    SIGNING_TYPEHASH(overrides?: CallOverrides): Promise<[string]>;

    giveMeMyToken(
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    name(overrides?: CallOverrides): Promise<[string]>;

    nonces(arg0: string, overrides?: CallOverrides): Promise<[number]>;

    pwn(
      token: BytesLike,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    pwnCounter(arg0: string, overrides?: CallOverrides): Promise<[BigNumber]>;

    signItLikeYouMeanIt(
      nonce: BigNumberish,
      deadline: BigNumberish,
      signature: BytesLike,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<ContractTransaction>;

    version(overrides?: CallOverrides): Promise<[string]>;
  };

  DOMAIN_SEPARATOR(overrides?: CallOverrides): Promise<string>;

  DOMAIN_TYPEHASH(overrides?: CallOverrides): Promise<string>;

  HackerWho(overrides?: CallOverrides): Promise<string>;

  SIGNING_TYPEHASH(overrides?: CallOverrides): Promise<string>;

  giveMeMyToken(
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  name(overrides?: CallOverrides): Promise<string>;

  nonces(arg0: string, overrides?: CallOverrides): Promise<number>;

  pwn(
    token: BytesLike,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  pwnCounter(arg0: string, overrides?: CallOverrides): Promise<BigNumber>;

  signItLikeYouMeanIt(
    nonce: BigNumberish,
    deadline: BigNumberish,
    signature: BytesLike,
    overrides?: Overrides & { from?: string | Promise<string> }
  ): Promise<ContractTransaction>;

  version(overrides?: CallOverrides): Promise<string>;

  callStatic: {
    DOMAIN_SEPARATOR(overrides?: CallOverrides): Promise<string>;

    DOMAIN_TYPEHASH(overrides?: CallOverrides): Promise<string>;

    HackerWho(overrides?: CallOverrides): Promise<string>;

    SIGNING_TYPEHASH(overrides?: CallOverrides): Promise<string>;

    giveMeMyToken(overrides?: CallOverrides): Promise<string>;

    name(overrides?: CallOverrides): Promise<string>;

    nonces(arg0: string, overrides?: CallOverrides): Promise<number>;

    pwn(token: BytesLike, overrides?: CallOverrides): Promise<void>;

    pwnCounter(arg0: string, overrides?: CallOverrides): Promise<BigNumber>;

    signItLikeYouMeanIt(
      nonce: BigNumberish,
      deadline: BigNumberish,
      signature: BytesLike,
      overrides?: CallOverrides
    ): Promise<void>;

    version(overrides?: CallOverrides): Promise<string>;
  };

  filters: {
    "TokenGen(address,bytes32)"(
      signer?: string | null,
      token?: BytesLike | null
    ): TypedEventFilter<[string, string], { signer: string; token: string }>;

    TokenGen(
      signer?: string | null,
      token?: BytesLike | null
    ): TypedEventFilter<[string, string], { signer: string; token: string }>;
  };

  estimateGas: {
    DOMAIN_SEPARATOR(overrides?: CallOverrides): Promise<BigNumber>;

    DOMAIN_TYPEHASH(overrides?: CallOverrides): Promise<BigNumber>;

    HackerWho(overrides?: CallOverrides): Promise<BigNumber>;

    SIGNING_TYPEHASH(overrides?: CallOverrides): Promise<BigNumber>;

    giveMeMyToken(
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    name(overrides?: CallOverrides): Promise<BigNumber>;

    nonces(arg0: string, overrides?: CallOverrides): Promise<BigNumber>;

    pwn(
      token: BytesLike,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    pwnCounter(arg0: string, overrides?: CallOverrides): Promise<BigNumber>;

    signItLikeYouMeanIt(
      nonce: BigNumberish,
      deadline: BigNumberish,
      signature: BytesLike,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<BigNumber>;

    version(overrides?: CallOverrides): Promise<BigNumber>;
  };

  populateTransaction: {
    DOMAIN_SEPARATOR(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    DOMAIN_TYPEHASH(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    HackerWho(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    SIGNING_TYPEHASH(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    giveMeMyToken(
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    name(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    nonces(
      arg0: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    pwn(
      token: BytesLike,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    pwnCounter(
      arg0: string,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    signItLikeYouMeanIt(
      nonce: BigNumberish,
      deadline: BigNumberish,
      signature: BytesLike,
      overrides?: Overrides & { from?: string | Promise<string> }
    ): Promise<PopulatedTransaction>;

    version(overrides?: CallOverrides): Promise<PopulatedTransaction>;
  };
}
