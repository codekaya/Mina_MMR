// MMRContract.ts
import {
  SmartContract,
  state,
  State,
  method,
  PublicKey,
  Signature,
  Struct,
  UInt64,
  Field,
  Bool,
  Poseidon,
  Provable
} from 'o1js';

const MAX_PEAKS = 10;

export class MMRProof extends Struct({
  elementIndex: UInt64,
  elementHash: Field,
  siblingsHashes: Provable.Array(Field, 16),
  peaksHashes: Provable.Array(Field, 16),
  elementsCount: UInt64,
}) {}

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
  */
  @method async verifyInclusion(
      leaf: Field,
      mmrproof: MMRProof,
      baggedHash: Field
  ) {
      this.mmrRoot.requireEquals(this.mmrRoot.get());
      let rootStored = this.mmrRoot.get();

      let { elementIndex, siblingsHashes, peaksHashes, elementsCount } = mmrproof;
      // Process siblings, skipping zeros
      let hash = leaf;
      for (let i = 0; i < mmrproof.siblingsHashes.length; i++) {
          let sibling = mmrproof.siblingsHashes[i];
          // Skip if sibling is zero
          let isZero = sibling.equals(Field(0));
          let newHash = Poseidon.hash([hash, sibling]);
          // Only update hash if sibling is not zero
          hash = Provable.if(isZero, hash, newHash);
      }

      // // Process peaks, skipping zeros
      let computedRoot = hash;
      for (let i = 0; i < mmrproof.peaksHashes.length; i++) {
          let peak = mmrproof.peaksHashes[i];
          let isZero = peak.equals(Field(0));
          let newRoot = Poseidon.hash([computedRoot, peak]);
          // Only update root if peak is not zero
          computedRoot = Provable.if(isZero, computedRoot, newRoot);
      }
      let finalRoot = Poseidon.hash([mmrproof.elementsCount.value, baggedHash]);
      finalRoot.assertEquals(rootStored);
  }
}

