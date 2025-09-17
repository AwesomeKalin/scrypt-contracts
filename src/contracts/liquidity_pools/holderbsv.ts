import { assert, ByteString, hash256, method, prop, SmartContract } from 'scrypt-ts';
import { TxUtil } from '../txUtil';

/**
 * Holds BSV for use in a liquidity pool.
 * Ensures that the relevant input's match the position and txid's of the outputs
 * Relocking is handled by the main contract
 */
export class LPHolderBSV extends SmartContract {
    @prop(false)
    readonly pos: bigint;

    constructor(pos: bigint) {
        super(...arguments);
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