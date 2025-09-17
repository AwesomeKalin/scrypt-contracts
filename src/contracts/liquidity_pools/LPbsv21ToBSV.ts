import { BSV20V2 } from "scrypt-ord";
import { ByteString, method, prop, assert, toByteString, hash256, slice, Utils, Addr, int2ByteString } from "scrypt-ts";
import { RabinPubKey, RabinSig, RabinVerifier } from "scrypt-ts-lib";
import { TxUtil } from "../txUtil";

/**
 * Main LP contract.
 * Locks a BSV21 token into a liquidity pool with BSV.
 * This contract holds the token as well as keeping track of the other token values
 */
export class LPBSV21ToBSV extends BSV20V2 {
    @prop(false)
    static holderBsvPrefix: ByteString = toByteString("2097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c0000000000", false);

    @prop(false)
    static holderBsvSuffix: ByteString = toByteString("76567a757171557a7559790141785a795a79210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce08105c7956795679aa7676517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e817757795679567956795679537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e6e9776009f636e936776687777777b757c6e5296a0636e7c947b757c6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f77545379935279930130787e527e54797e58797e527e53797e52797e57797e6b6d6d6d6d6d6d6c765779ac6b6d6d6d6d6d6c776959797601247f75547f7777547a7572537a59797601687f7501447f777701207f77817b757c59797601687f7501447f777701207f75007f77537a757b7b5879aa54798858797d775279567955796f759d76547900760124955279780120937f75787f6b6d6d6c7888515379519c63527768557978760124955279780120937f75787f6b6d6d6c5279886d6d6d516b6d6d6d6d6d6c", false);

    @prop(false)
    static holderBsv21Prefix: ByteString = toByteString("2097dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff0262102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382201008ce7480da41702918d1ec8e6849ba32b4d65b1e40dc669c31a1e6306b266c00000000000000000000", false);

    @prop(false)
    static holderBsv21Suffix: ByteString = toByteString("52795e7a755d7a5d7a5d7a5d7a5d7a5d7a5d7a5d7a5d7a5d7a5d7a5d7a5d7a785d7a755c7a5c7a5c7a5c7a5c7a5c7a5c7a5c7a5c7a5c7a5c7a5c7a54795f7a755e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a53795c7a755b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5b7a5d7909ffffffffffffffff00a1695c790112a169765b7a755a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a5a7a6d6d755e797601687f7700005279517f75007f7d7701fd87635379537f75517f777601007e8177537a757b7b5379535479937f75537f777b757c677601fe87635379557f75517f777601007e8177537a757b7b5379555479937f75557f777b757c677601ff87635379597f75517f777601007e8177537a757b7b5379595479937f75597f777b757c675379517f75007f777601007e8177537a757b7b5379515479937f75517f777b757c68686875777777767682776e8c7f757854948c7f7d77815279789454948c6b6d6d6c6e7f75537a757b7b0000707f7776537a757777006e8b7f75787f7778768b537a75777c0100788791777664005379007855798b7f7555797f77815579768b577a75567a567a567a567a567a567a7877014c9f6376547a7572537a527956795579937f7556797f777b757c6776014c9c63527956798b7f7556797f777601007e8177547a7572537a55798b567a757171557a557975527956795579937f7556797f777b757c6776014d9c635279567952937f7556797f777601007e8177547a7572537a55795293567a757171557a557975527956795579937f7556797f777b757c6776014e9c635279567954937f7556797f777601007e8177547a7572537a55795493567a757171557a557975527956795579937f7556797f777b757c670069686868685579547993567a757171557a55796d77775f7a755e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a5e7a68011379014178011479011479210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda43ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce081001167956795679aa7676517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e817757795679567956795679537956795479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff006e6e9776009f636e936776687777777b757c6e5296a0636e7c947b757c6853798277527982775379012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279947f77545379935279930130787e527e54797e58797e527e53797e52797e57797e6b6d6d6d6d6d6d6c765779ac6b6d6d6d6d6d6c77690113797601247f75547f77775a7a75597a597a597a597a597a597a597a597a597a0113797601687f7501447f777701207f7781587a75577a577a577a577a577a577a577a0113797601687f7501447f777701207f75007f77597a75587a587a587a587a587a587a587a587a011279aa5a7988011279577a75567a567a567a567a567a567a567958795c795b796f759d76547900760124955279780120937f75787f6b6d6d6c7888515379519c63527768557978760124955279780120937f75787f6b6d6d6c5279886d6d6d516b6d6d6d6d6d6d6d6d6d6d6c", false);

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

    @prop(true)
    bsv21TokenAmt: bigint;

    @prop(true)
    bsvAmt: bigint;

    @prop(true)
    lpTokenAmt: bigint;

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
        oraclePubKey: RabinPubKey
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
    }

    // Parses messages from the oracle
    @method()
    static verifyTokenMessage(oracleMsg: ByteString, outputTx: ByteString, outputIdx: bigint): bigint {
        const messageTx: ByteString = slice(oracleMsg, 0n, 32n);
        const messageIdx: bigint = Utils.fromLEUnsigned(slice(oracleMsg, 32n, 40n));

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
        address: Addr
    ) {
        // Verify position
        assert(this.ctx.utxo.outpoint.outputIndex === 0n, 'must be in 0th position');

        // Verify token input and get amount of tokens
        const tokenOutputTx: ByteString = TxUtil.getPrevoutTxid(this.prevouts, 3n);
        const tokenOutputIdx: bigint = TxUtil.getPrevoutOutputIdx(this.prevouts, 3n);

        assert(RabinVerifier.verifySig(oracleMsg, oracleSig, this.oraclePubKey), 'invalid rabin signature');
        const tokenAmt: bigint = LPBSV21ToBSV.verifyTokenMessage(oracleMsg, tokenOutputTx, tokenOutputIdx);

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
        assert(bsvValue === neededBsv, 'inputted incorrect amount of BSV');

        // Calculate LP Tokens to give
        const lpTokensToGive: bigint = ((this.lpTokenMax - this.lpTokenAmt) / this.bsv21TokenAmt) * tokenAmt;

        // Update values
        this.bsv21TokenAmt += tokenAmt;
        this.bsvAmt += bsvValue;
        this.lpTokenAmt -= lpTokensToGive;

        // Create outputs
        let outputs: ByteString = this.buildStateOutputFT(this.bsv21TokenAmt);
        
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

        outputs += Utils.buildOutput(BSV20V2.createTransferInsciption(this.lpTokenId, this.lpTokenAmt) + lpHoldScript, 1n);
        outputs += BSV20V2.buildTransferOutput(address, this.lpTokenId, this.lpTokenAmt);
        outputs += this.buildChangeOutput();

        assert(hash256(outputs) == this.ctx.hashOutputs, 'hashOutputs mismatch');
    }
}