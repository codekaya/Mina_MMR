// MMRContract.ts
import {
    SmartContract,
    state,
    State,
    method,
    PublicKey,
    Signature,
    Field,
    Bool,
    Poseidon,
  } from 'o1js';
  

  const MAX_PEAKS = 10;
  /**
   * A minimal zkApp that stores a single MMR root in on-chain state.
   */
  export class MMRContract extends SmartContract {
    // The on-chain commitment (MMR root).
    @state(Field) mmrRoot = State<Field>();
  
    /**
     * Initialize the contract: set mmrRoot to Field(0).
     */
    @method async init() {
      super.init();
      this.mmrRoot.set(Field(0));
    }
  
    /**
     * Public method to update the on-chain MMR root.
     * In a real app, you'd do permission checks or signatures.
     */
    @method async updateRoot(newRoot: Field) {
      // For now, we just store it. (You might require a signature, etc.)
      this.mmrRoot.set(newRoot);
    }
  
    /**
     * Verifies an inclusion proof against the on-chain MMR root.
     * This method doesn't reconstruct the entire MMR, only checks:
     *  1) The leaf + proof => computed root
     *  2) Compare computed root == mmrRoot
     *
     * We assume you pass in `leaf`, `siblings`, `peaks`, etc. in a format
     * consistent with your library’s proof. We'll show a simplified version.
     */
    @method async verifyInclusion(
      leaf: Field,
      siblings: Field[],
      peaks: Field[],
      index: Field // or UInt64, depending on your code
    ) {
      // read the stored root
      let rootStored = this.mmrRoot.get();
      //this.mmrRoot.assertEquals(rootStored);
  
      // Here, you'd do the same "reconstruct the peak from the proof" logic
      // that your `verifyProof` method does off-chain or in your library.
      // For simplicity, let's just do a hashed chain:
      let hash = leaf;
      for (let i = 0; i < siblings.length; i++) {
        // this is a naive pairing, left vs right
        hash = Poseidon.hash([hash, siblings[i]]);
      }
      // Then combine with peaks, etc., or do your bagThePeaks logic in-circuit
  
      // For demonstration, let computedRoot = Poseidon.hash([hash, ...peaks])
      let computedRoot = hash;
      for (let i = 0; i < peaks.length; i++) {
        computedRoot = Poseidon.hash([computedRoot, peaks[i]]);
      }
  
      // Return whether the computed root equals the on-chain root
      computedRoot.assertEquals(rootStored);
    }
  }
  