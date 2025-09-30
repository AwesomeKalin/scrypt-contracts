import { BSV20V2 } from 'scrypt-ord';
import {
    ByteString,
    method,
    prop,
    assert,
    toByteString,
    hash256,
    slice,
    Utils,
    Addr,
    int2ByteString,
    MethodCallOptions,
    ContractTransaction,
    bsv,
} from 'scrypt-ts';
import { RabinPubKey, RabinSig, RabinVerifier } from 'scrypt-ts-lib';
import { TxUtil } from '../txUtil';

import Transaction = bsv.Transaction;
import { LPHolderBSV } from './holderbsv';
import { LPHolderBSV21 } from './holderbsv21';

/**
 * Main LP contract.
 * Locks a BSV21 token into a liquidity pool with BSV.
 * This contract holds the token as well as keeping track of the other token values
 */
export class LPBSV21ToBSV extends BSV20V2 {
    @prop(false)
    static holderBsvPrefix: ByteString = toByteString(
        '2097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c0000000000',
        false
    );

    @prop(false)
    static holderBsvSuffix: ByteString = toByteString(
        '76567a757171557a7559790141785a795a79210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce08105c7956795679aa7676517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e817757795679567956795679537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e6e9776009f636e936776687777777b757c6e5296a0636e7c947b757c6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f77545379935279930130787e527e54797e58797e527e53797e52797e57797e6b6d6d6d6d6d6d6c765779ac6b6d6d6d6d6d6c776959797601247f75547f7777547a7572537a59797601687f7501447f777701207f77817b757c59797601687f7501447f777701207f75007f77537a757b7b5879aa54798858797d775279567955796f759d76547900760124955279780120937f75787f6b6d6d6c7888515379519c63527768557978760124955279780120937f75787f6b6d6d6c5279886d6d6d516b6d6d6d6d6d6c',
        false
    );

    @prop(false)
    static holderBsv21Prefix: ByteString = toByteString(
        '2097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c00000000000000000000',
        false
    );

    @prop(false)
    static holderBsv21Suffix: ByteString = toByteString(
        '52795e7a755d7a5d7a5d7a5d7a5d7a5d7a5d7a5d7a5d7a5d7a5d7a5d7a5d7a785d7a755c7a5c7a5c7a5c7a5c7a5c7a5c7a5c7a5c7a5c7a5c7a5c7a54795f7a755e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a53795c7a755b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5d7909ffffffffffffffff00a1695c790112a169765b7a755a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a6d6d755e797601687f7700005279517f75007f7d7701fd87635379537f75517f777601007e8177537a757b7b5379535479937f75537f777b757c677601fe87635379557f75517f777601007e8177537a757b7b5379555479937f75557f777b757c677601ff87635379597f75517f777601007e8177537a757b7b5379595479937f75597f777b757c675379517f75007f777601007e8177537a757b7b5379515479937f75517f777b757c68686875777777767682776e8c7f757854948c7f7d77815279789454948c6b6d6d6c6e7f75537a757b7b0000707f7776537a757777006e8b7f75787f7778768b537a75777c0100788791777664005379007855798b7f7555797f77815579768b577a75567a567a567a567a567a567a7877014c9f6376547a7572537a527956795579937f7556797f777b757c6776014c9c63527956798b7f7556797f777601007e8177547a7572537a55798b567a757171557a557975527956795579937f7556797f777b757c6776014d9c635279567952937f7556797f777601007e8177547a7572537a55795293567a757171557a557975527956795579937f7556797f777b757c6776014e9c635279567954937f7556797f777601007e8177547a7572537a55795493567a757171557a557975527956795579937f7556797f777b757c670069686868685579547993567a757171557a55796d77775f7a755e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a68011379014178011479011479210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce081001167956795679aa7676517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e817757795679567956795679537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e6e9776009f636e936776687777777b757c6e5296a0636e7c947b757c6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f77545379935279930130787e527e54797e58797e527e53797e52797e57797e6b6d6d6d6d6d6d6c765779ac6b6d6d6d6d6d6c77690113797601247f75547f77775a7a75597a597a597a597a597a597a597a597a597a0113797601687f7501447f777701207f7781587a75577a577a577a577a577a577a577a0113797601687f7501447f777701207f75007f77597a75587a587a587a587a587a587a587a587a011279aa5a7988011279577a75567a567a567a567a567a567a567958795c795b796f759d76547900760124955279780120937f75787f6b6d6d6c7888515379519c63527768557978760124955279780120937f75787f6b6d6d6c5279886d6d6d516b6d6d6d6d6d6d6d6d6d6d6c',
        false
    );

    @prop(false)
    readonly oraclePubKey: RabinPubKey;

    @prop(false)
    readonly lpTokenId: ByteString;

    @prop(false)
    readonly lpTokenSym: ByteString;

    @prop(false)
    readonly lpTokenMax: bigint;

    @prop(false)
    readonly lpTokenDec: bigint;

    @prop(false)
    readonly bsv21TokenFund: Addr;

    @prop(false)
    readonly lpTokenFund: Addr;

    @prop(true)
    bsv21TokenAmt: bigint;

    @prop(true)
    bsvAmt: bigint;

    @prop(true)
    lpTokenAmt: bigint;

    @prop(true)
    bsv21Fees: bigint;

    @prop(true)
    bsvFees: bigint;

    constructor(
        id: ByteString,
        sym: ByteString,
        max: bigint,
        dec: bigint,
        initialBsv21TokenAmt: bigint,
        initialBsvAmt: bigint,
        lpTokenId: ByteString,
        lpTokenSym: ByteString,
        lpTokenMax: bigint,
        lpTokenDec: bigint,
        lpTokenAmt: bigint,
        oraclePubKey: RabinPubKey,
        bsv21TokenFund: Addr,
        lpTokenFund: Addr
    ) {
        super(id, sym, max, dec);
        this.init(...arguments);

        // Set amount of tokens
        this.bsv21TokenAmt = initialBsv21TokenAmt;
        this.bsvAmt = initialBsvAmt;
        this.lpTokenAmt = lpTokenAmt;

        // Set LP Token Details
        this.lpTokenId = lpTokenId;
        this.lpTokenSym = lpTokenSym;
        this.lpTokenMax = lpTokenMax;
        this.lpTokenDec = lpTokenDec;

        // Oracle Pub Key
        this.oraclePubKey = oraclePubKey;

        // Set fund addresses
        this.bsv21TokenFund = bsv21TokenFund;
        this.lpTokenFund = lpTokenFund;

        // Set collected fees to 0
        this.bsv21Fees = 0n;
        this.bsvFees = 0n;
    }

    // Parses messages from the oracle
    @method()
    static verifyTokenMessage(
        oracleMsg: ByteString,
        outputTx: ByteString,
        outputIdx: bigint
    ): bigint {
        const messageTx: ByteString = slice(oracleMsg, 0n, 32n);
        const messageIdx: bigint = Utils.fromLEUnsigned(
            slice(oracleMsg, 32n, 40n)
        );

        assert(messageTx === outputTx, 'incorrect token output');
        assert(messageIdx === outputIdx, 'incorrect token output');

        return Utils.fromLEUnsigned(slice(oracleMsg, 40n));
    }

    // Adds liquidity to the pool, using an oracle to verify tokens
    @method()
    public addLiquidityWithOracle(
        oracleMsg: ByteString,
        oracleSig: RabinSig,
        bsvInputTx: ByteString,
        script: ByteString
    ) {
        // Verify positions
        assert(
            this.ctx.utxo.outpoint.outputIndex === 0n,
            'must be in 0th position'
        );

        TxUtil.verifyHolders(this.prevouts, this.ctx.utxo.outpoint.txid);

        // Verify token input and get amount of tokens
        const tokenOutputTx: ByteString = TxUtil.getPrevoutTxid(
            this.prevouts,
            3n
        );

        const tokenOutputIdx: bigint = TxUtil.getPrevoutOutputIdx(
            this.prevouts,
            3n
        );

        assert(
            RabinVerifier.verifySig(oracleMsg, oracleSig, this.oraclePubKey),
            'invalid rabin signature'
        );

        const tokenAmt: bigint = LPBSV21ToBSV.verifyTokenMessage(
            oracleMsg,
            tokenOutputTx,
            tokenOutputIdx
        );

        // Calculate amount of BSV needed
        const ratioBsv21ToBSV: bigint = this.bsvAmt / this.bsv21TokenAmt;
        const neededBsv: bigint = tokenAmt * ratioBsv21ToBSV;

        // Get input of BSV
        const bsvTx: ByteString = TxUtil.getPrevoutTxid(this.prevouts, 4n);
        const bsvIdx: bigint = TxUtil.getPrevoutOutputIdx(this.prevouts, 4n);

        // Verify provided transaction
        assert(hash256(bsvInputTx) === bsvTx, 'provided incorrect tx');

        // Get value of input
        const bsvValue: bigint = TxUtil.readOutput(bsvInputTx, bsvIdx).satoshis;
        assert(bsvValue >= neededBsv, 'inputted incorrect amount of BSV');

        // Calculate LP Tokens to give
        const lpTokensToGive: bigint =
            ((this.lpTokenMax - this.lpTokenAmt) / this.bsv21TokenAmt) *
            tokenAmt;

        // Update values
        this.bsv21TokenAmt += tokenAmt;
        this.bsvAmt += bsvValue;
        this.lpTokenAmt -= lpTokensToGive;

        // Create outputs
        let outputs: ByteString = this.buildStateOutputFT(this.bsv21TokenAmt);

        // Holders
        const bsvHoldScript: ByteString =
            LPBSV21ToBSV.holderBsvPrefix +
            int2ByteString(1n) +
            LPBSV21ToBSV.holderBsvSuffix;

        outputs += Utils.buildOutput(bsvHoldScript, this.bsvAmt);

        const lpHoldScript: ByteString =
            LPBSV21ToBSV.holderBsv21Prefix +
            this.lpTokenId +
            this.lpTokenSym +
            int2ByteString(this.lpTokenMax) +
            int2ByteString(this.lpTokenDec) +
            int2ByteString(2n) +
            LPBSV21ToBSV.holderBsv21Suffix;

        outputs += Utils.buildOutput(
            BSV20V2.createTransferInsciption(this.lpTokenId, this.lpTokenAmt) +
                lpHoldScript,
            1n
        );

        // Payout LP Tokens
        outputs += Utils.buildOutput(
            BSV20V2.createTransferInsciption(this.lpTokenId, lpTokensToGive) +
                script,
            1n
        );

        // BSV21 Indexing Fund Outputs
        outputs += Utils.buildAddressOutput(this.bsv21TokenFund, 1000n);
        outputs += Utils.buildAddressOutput(this.lpTokenFund, 2000n);

        // Change
        outputs += this.buildChangeOutput();

        assert(
            hash256(outputs) == this.ctx.hashOutputs,
            'hashOutputs mismatch'
        );
    }

    // TODO: Add liquidity using full transaction verification on-chain

    // Swap the BSV21 token, using an oracle for token verification
    @method()
    public swapTokenToBSVWithOracle(
        oracleMsg: ByteString,
        oracleSig: RabinSig,
        script: ByteString,
        appScript: ByteString
    ) {
        // Verify positions
        assert(
            this.ctx.utxo.outpoint.outputIndex === 0n,
            'must be in 0th position'
        );

        TxUtil.verifyHolders(this.prevouts, this.ctx.utxo.outpoint.txid);

        // Verify token input and get amount of tokens
        const tokenOutputTx: ByteString = TxUtil.getPrevoutTxid(
            this.prevouts,
            3n
        );

        const tokenOutputIdx: bigint = TxUtil.getPrevoutOutputIdx(
            this.prevouts,
            3n
        );

        assert(
            RabinVerifier.verifySig(oracleMsg, oracleSig, this.oraclePubKey),
            'invalid rabin signature'
        );

        const tokenAmt: bigint = LPBSV21ToBSV.verifyTokenMessage(
            oracleMsg,
            tokenOutputTx,
            tokenOutputIdx
        );

        // Calculate x * y = k
        const k: bigint = this.bsv21TokenAmt * this.bsvAmt;

        // Calculate BSV to give to user
        const newYValue: bigint = k / (this.bsv21TokenAmt + tokenAmt);
        let bsvToGive: bigint = this.bsvAmt - newYValue;

        // Calculate and subtract fees
        const fee: bigint = (bsvToGive * 1000n * 5n) / 1000000n;
        const lpFee: bigint = (fee / 6n) * 5n;
        const appFee: bigint = fee - lpFee;

        bsvToGive -= fee;

        // Update values
        this.bsv21TokenAmt += tokenAmt;
        this.bsvAmt -= bsvToGive;
        this.bsvFees += lpFee;

        // Create outputs
        let outputs: ByteString = this.buildStateOutputFT(this.bsv21TokenAmt);

        // Holders
        const bsvHoldScript: ByteString =
            LPBSV21ToBSV.holderBsvPrefix +
            int2ByteString(1n) +
            LPBSV21ToBSV.holderBsvSuffix;

        outputs += Utils.buildOutput(bsvHoldScript, this.bsvAmt);

        const lpHoldScript: ByteString =
            LPBSV21ToBSV.holderBsv21Prefix +
            this.lpTokenId +
            this.lpTokenSym +
            int2ByteString(this.lpTokenMax) +
            int2ByteString(this.lpTokenDec) +
            int2ByteString(2n) +
            LPBSV21ToBSV.holderBsv21Suffix;

        outputs += Utils.buildOutput(
            BSV20V2.createTransferInsciption(this.lpTokenId, this.lpTokenAmt) +
                lpHoldScript,
            1n
        );

        // Payout BSV
        outputs += Utils.buildOutput(script, bsvToGive);

        // App fees
        outputs += Utils.buildOutput(appScript, appFee);

        // BSV21 Indexing Fund Outputs
        outputs += Utils.buildAddressOutput(this.bsv21TokenFund, 1000n);
        outputs += Utils.buildAddressOutput(this.lpTokenFund, 1000n);

        // Change
        outputs += this.buildChangeOutput();

        assert(
            hash256(outputs) == this.ctx.hashOutputs,
            'hashOutputs mismatch'
        );
    }

    // Swap BSV to the BSV21 token. No oracle is required and can easily be verified on-chain
    @method()
    public swapBSVtoToken(
        bsvInputTx: ByteString,
        script: ByteString,
        appScript: ByteString
    ) {
        // Verify positions
        assert(
            this.ctx.utxo.outpoint.outputIndex === 0n,
            'must be in 0th position'
        );

        TxUtil.verifyHolders(this.prevouts, this.ctx.utxo.outpoint.txid);

        // Get input of BSV
        const bsvTx: ByteString = TxUtil.getPrevoutTxid(this.prevouts, 3n);
        const bsvIdx: bigint = TxUtil.getPrevoutOutputIdx(this.prevouts, 3n);

        // Verify provided transaction
        assert(hash256(bsvInputTx) === bsvTx, 'provided incorrect tx');

        // Get value of input
        const bsvValue: bigint = TxUtil.readOutput(bsvInputTx, bsvIdx).satoshis;

        // Calculate x * y = k
        const k: bigint = this.bsv21TokenAmt * this.bsvAmt;

        // Calculate BSV to give to user
        const newXValue: bigint = k / (this.bsvAmt + bsvValue);
        let bsv21ToGive: bigint = this.bsv21TokenAmt - newXValue;

        // Calculate and subtract fees
        const fee: bigint = (bsv21ToGive * 1000n * 5n) / 1000000n;
        const lpFee: bigint = (fee / 6n) * 5n;
        const appFee: bigint = fee - lpFee;

        bsv21ToGive -= fee;

        // Update values
        this.bsv21TokenAmt -= bsv21ToGive;
        this.bsvAmt += bsvValue;
        this.bsv21Fees += lpFee;

        // Create outputs
        let outputs: ByteString = this.buildStateOutputFT(this.bsv21TokenAmt);

        // Holders
        const bsvHoldScript: ByteString =
            LPBSV21ToBSV.holderBsvPrefix +
            int2ByteString(1n) +
            LPBSV21ToBSV.holderBsvSuffix;

        outputs += Utils.buildOutput(bsvHoldScript, this.bsvAmt);

        const lpHoldScript: ByteString =
            LPBSV21ToBSV.holderBsv21Prefix +
            this.lpTokenId +
            this.lpTokenSym +
            int2ByteString(this.lpTokenMax) +
            int2ByteString(this.lpTokenDec) +
            int2ByteString(2n) +
            LPBSV21ToBSV.holderBsv21Suffix;

        outputs += Utils.buildOutput(
            BSV20V2.createTransferInsciption(this.lpTokenId, this.lpTokenAmt) +
                lpHoldScript,
            1n
        );

        // Payout Tokens
        outputs += Utils.buildOutput(
            BSV20V2.createTransferInsciption(this.id, bsv21ToGive) + script,
            1n
        );

        // App Fees
        outputs += Utils.buildOutput(
            BSV20V2.createTransferInsciption(this.id, appFee) + appScript,
            1n
        );

        // BSV21 Indexing Fund Outputs
        outputs += Utils.buildAddressOutput(this.bsv21TokenFund, 2000n);
        outputs += Utils.buildAddressOutput(this.lpTokenFund, 1000n);

        // Change
        outputs += this.buildChangeOutput();

        assert(
            hash256(outputs) == this.ctx.hashOutputs,
            'hashOutputs mismatch'
        );
    }

    // Removes liquidity from the pool, using an oracle to verify tokens
    @method()
    public removeLiquidityWithOracle(
        oracleMsg: ByteString,
        oracleSig: RabinSig,
        bsv21Script: ByteString,
        bsvScript: ByteString
    ) {
        // Verify positions
        assert(
            this.ctx.utxo.outpoint.outputIndex === 0n,
            'must be in 0th position'
        );

        TxUtil.verifyHolders(this.prevouts, this.ctx.utxo.outpoint.txid);

        // Verify token input and get amount of tokens
        const tokenOutputTx: ByteString = TxUtil.getPrevoutTxid(
            this.prevouts,
            3n
        );

        const tokenOutputIdx: bigint = TxUtil.getPrevoutOutputIdx(
            this.prevouts,
            3n
        );

        assert(
            RabinVerifier.verifySig(oracleMsg, oracleSig, this.oraclePubKey),
            'invalid rabin signature'
        );

        const lpTokenAmt: bigint = LPBSV21ToBSV.verifyTokenMessage(
            oracleMsg,
            tokenOutputTx,
            tokenOutputIdx
        );

        // Calculate withdrawal amount w/o fees
        const ratioLpToBSV21: bigint =
            (this.lpTokenMax - this.lpTokenAmt) / this.bsv21TokenAmt;
        const bsv21AmtNoFees: bigint = lpTokenAmt * ratioLpToBSV21;

        const ratioBsv21ToBSV: bigint = this.bsvAmt / this.bsv21TokenAmt;
        const bsvAmtNoFees: bigint = bsv21AmtNoFees * ratioBsv21ToBSV;

        // Calculate with fees
        const ratioLpToBSV21Fees: bigint =
            (this.lpTokenMax - this.lpTokenAmt) / this.bsv21Fees;
        const bsv21FeesAmt: bigint = lpTokenAmt * ratioLpToBSV21Fees;

        const ratioLpToBSVFees: bigint =
            (this.lpTokenMax - this.lpTokenAmt) / this.bsvFees;
        const bsvFeesAmt: bigint = lpTokenAmt * ratioLpToBSVFees;

        // Update Values
        this.bsv21TokenAmt -= bsv21AmtNoFees;
        this.bsvAmt -= bsvAmtNoFees;

        this.bsv21Fees -= bsv21FeesAmt;
        this.bsvFees -= bsvFeesAmt;

        this.lpTokenAmt += lpTokenAmt;

        let outputs: ByteString = toByteString('');

        if (this.bsv21TokenAmt === 0n && this.bsvAmt === 0n) {
            // Payout BSV21 token and BSV
            outputs += Utils.buildOutput(
                BSV20V2.createTransferInsciption(
                    this.id,
                    bsv21AmtNoFees + bsv21FeesAmt
                ) + bsv21Script,
                1n
            );
            outputs += Utils.buildOutput(bsvScript, bsvAmtNoFees + bsvFeesAmt);

            // BSV21 Indexing Fund Outputs
            outputs += Utils.buildAddressOutput(this.bsv21TokenFund, 1000n);
        } else {
            // Create outputs
            outputs += this.buildStateOutputFT(this.bsv21TokenAmt);

            // Holders
            const bsvHoldScript: ByteString =
                LPBSV21ToBSV.holderBsvPrefix +
                int2ByteString(1n) +
                LPBSV21ToBSV.holderBsvSuffix;

            outputs += Utils.buildOutput(bsvHoldScript, this.bsvAmt);

            const lpHoldScript: ByteString =
                LPBSV21ToBSV.holderBsv21Prefix +
                this.lpTokenId +
                this.lpTokenSym +
                int2ByteString(this.lpTokenMax) +
                int2ByteString(this.lpTokenDec) +
                int2ByteString(2n) +
                LPBSV21ToBSV.holderBsv21Suffix;

            outputs += Utils.buildOutput(
                BSV20V2.createTransferInsciption(
                    this.lpTokenId,
                    this.lpTokenAmt
                ) + lpHoldScript,
                1n
            );

            // Payout BSV21 token and BSV
            outputs += Utils.buildOutput(
                BSV20V2.createTransferInsciption(
                    this.id,
                    bsv21AmtNoFees + bsv21FeesAmt
                ) + bsv21Script,
                1n
            );
            outputs += Utils.buildOutput(bsvScript, bsvAmtNoFees + bsvFeesAmt);

            // BSV21 Indexing Fund Outputs
            outputs += Utils.buildAddressOutput(this.bsv21TokenFund, 2000n);
            outputs += Utils.buildAddressOutput(this.lpTokenFund, 1000n);
        }

        // Change
        outputs += this.buildChangeOutput();

        assert(
            hash256(outputs) == this.ctx.hashOutputs,
            'hashOutputs mismatch'
        );
    }

    // Transaction builder for liquidity adding functions
    static buildTxForAddLiquidity(
        current: LPBSV21ToBSV,
        holderBSV: LPHolderBSV,
        holderLP: LPHolderBSV21,
        tokenDeposit: Transaction.Input,
        options: MethodCallOptions<LPBSV21ToBSV>,
        oracleMsg: ByteString,
        oracleSig: RabinSig,
        bsvInputTx: ByteString,
        script: ByteString
    ): Promise<ContractTransaction> {
        const nextInstance = current.next();

        // Update contract values. See actual functions for proper commenting of functionality
        const tokenOutputTx: ByteString = TxUtil.getPrevoutTxid(
            nextInstance.prevouts,
            3n
        );

        const tokenOutputIdx: bigint = TxUtil.getPrevoutOutputIdx(
            nextInstance.prevouts,
            3n
        );

        const tokenAmt: bigint = LPBSV21ToBSV.verifyTokenMessage(
            oracleMsg,
            tokenOutputTx,
            tokenOutputIdx
        );

        const bsvIdx: bigint = TxUtil.getPrevoutOutputIdx(
            nextInstance.prevouts,
            4n
        );
        const bsvValue: bigint = TxUtil.readOutput(bsvInputTx, bsvIdx).satoshis;

        const lpTokensToGive: bigint =
            ((current.lpTokenMax - current.lpTokenAmt) /
                current.bsv21TokenAmt) *
            tokenAmt;

        nextInstance.bsv21TokenAmt += tokenAmt;
        nextInstance.bsvAmt += bsvValue;
        nextInstance.lpTokenAmt -= lpTokensToGive;

        const LPHolderBSVnext = new LPHolderBSV(1n);
        const LPHolderBSV21next = new LPHolderBSV21(
            nextInstance.lpTokenId,
            nextInstance.lpTokenSym,
            nextInstance.lpTokenMax,
            nextInstance.lpTokenDec,
            2n
        );

        // Create unsigned transaction
        const unsignedTx: Transaction = new Transaction()
            .addInput(current.buildContractInput())
            .addInput(holderBSV.buildContractInput())
            .addInput(holderLP.buildContractInput())
            .addInput(tokenDeposit)
            .addOutput(
                new Transaction.Output({
                    script: nextInstance.lockingScript,
                    satoshis: 1,
                })
            )
            .addOutput(
                new Transaction.Output({
                    script: LPHolderBSVnext.lockingScript,
                    satoshis: Number(
                        nextInstance.bsvAmt + nextInstance.bsvFees
                    ),
                })
            )
            .addOutput(
                new Transaction.Output({
                    script: LPHolderBSV21next.lockingScript,
                    satoshis: 1,
                })
            )
            .addOutput(
                new Transaction.Output({
                    script: new bsv.Script(
                        BSV20V2.createTransferInsciption(
                            nextInstance.lpTokenId,
                            current.lpTokenAmt - nextInstance.lpTokenAmt
                        ) + script
                    ),
                    satoshis: 1,
                })
            )
            .addOutput(
                new Transaction.Output({
                    script: bsv.Script.fromHex(
                        Utils.buildPublicKeyHashScript(current.bsv21TokenFund)
                    ),
                    satoshis: 1000,
                })
            )
            .addOutput(
                new Transaction.Output({
                    script: bsv.Script.fromHex(
                        Utils.buildPublicKeyHashScript(current.lpTokenFund)
                    ),
                    satoshis: 2000,
                })
            );

        if (options.changeAddress) {
            // build change output
            unsignedTx.change(options.changeAddress);
        }

        return Promise.resolve({
            tx: unsignedTx,
            atInputIndex: 0,
            nexts: [
                {
                    instance: nextInstance,
                    atOutputIndex: 0,
                    balance: 1,
                },
                {
                    instance: LPHolderBSVnext,
                    atOutputIndex: 1,
                    balance: Number(nextInstance.bsvAmt + nextInstance.bsvFees),
                },
                {
                    instance: LPHolderBSV21next,
                    atOutputIndex: 2,
                    balance: 1,
                },
            ],
        });
    }
}
