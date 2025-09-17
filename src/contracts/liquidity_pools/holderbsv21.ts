import { BSV20V2 } from 'scrypt-ord';
import { assert, ByteString, method, prop } from 'scrypt-ts';
import { TxUtil } from '../txUtil';

/**
 * Holds a BSV21 token for use in a liquidity pool.
 * Ensures that the relevant input's match the position and txid's of the outputs
 * Relocking is handled by the main contract
 */
export class LPHolderBSV21 extends BSV20V2 {
    @prop(false)
    readonly pos: bigint;

    constructor(id: ByteString, sym: ByteString, max: bigint, dec: bigint, pos: bigint) {
        super(id, sym, max, dec);
        this.init(...arguments);
        this.pos = pos;
    }
    
    @method()
    public unlock() {
        assert(
            TxUtil.unlockHolder(
                this.prevouts, 
                this.ctx.utxo.outpoint.outputIndex, 
                this.pos, 
                this.ctx.utxo.outpoint.txid,
            )
        );
    }
}