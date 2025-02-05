// Mmr.ts

import {
  Field,
  SmartContract,
  UInt64,
  Struct,
  Poseidon,
  state,
  State,
  method,
  Bool,
  Provable,
} from 'o1js';

const MAX_ELEMENTS = 32;  
const MAX_PEAKS = 8;   

/**
 * Proof structure for inclusion proofs.
 */
export class Proof extends Struct({
  elementIndex: UInt64,
  elementHash: Field,
  siblingsHashes: Provable.Array(Field, MAX_PEAKS), 
  peaksHashes: Provable.Array(Field, MAX_PEAKS),    
  siblingsLength: UInt64,
  peaksLength: UInt64,
  elementsCount: UInt64,
}) {}

/**
 * Merkle Mountain Range class.
 */
export class MerkleMountainRange extends Struct({
  leavesCount: UInt64,
  elementsCount: UInt64,
  hashes: Provable.Array(Field, MAX_ELEMENTS), 
  rootHash: Field,
}) {
  constructor() {
    const initialData = Array(MAX_ELEMENTS).fill(Field(0));
    super({
      leavesCount: UInt64.zero,
      elementsCount: UInt64.zero,
      hashes: initialData,
      rootHash: Field(0),
    });
  }

  /**
   * Appends a new leaf to the MMR.
   *
   * The function first adds the new leaf, then (if there are at least two peaks)
   * merges the right‐most peaks. (When merging, it "allocates" one new parent node.)
   */
  append(value: Field): {
    leavesCount: UInt64;
    elementsCount: UInt64;
    elementIndex: UInt64;
    rootHash: Field;
  } {
    let elementsCount = this.elementsCount;
    const peaksIndices = findPeaks(elementsCount);
    
    // Create peaks array 
    let provablePeaks = Provable.witness(
      Provable.Array(Field, MAX_PEAKS),
      () => {
        const peaks = this.retrievePeaksHashes(peaksIndices);
        return peaks; 
      }
    );
    
    let peaksLength = UInt64.from(peaksIndices.length);
    
    // Increment elementsCount for the new leaf
    elementsCount = elementsCount.add(UInt64.one);
    let lastElementIdx = elementsCount;
    const leafElementIndex = lastElementIdx;

    // Store the new leaf's hash in the state array
    this.hashes = Provable.witness(
      Provable.Array(Field, MAX_ELEMENTS),
      () => {
        let newHashes = [...this.hashes];
        newHashes[Number(lastElementIdx.toBigInt())] = value;
        return newHashes;
      }
    );

    // Add the new leaf to the peaks (it will be the right‐most peak)
    provablePeaks = Provable.witness(Provable.Array(Field, MAX_PEAKS), () => {
      let newPeaks = [...provablePeaks];
      newPeaks[Number(peaksLength.toBigInt())] = value;
      return newPeaks;
    });
    peaksLength = peaksLength.add(UInt64.one);

    let height = UInt64.zero;
    // --- MERGE LOOP ---
    for (let i = 0; i < MAX_PEAKS; i++) {
      // If there are fewer than two peaks or the new leaf’s tree is not complete, break.
      if (
        !(
          peaksLength.greaterThanOrEqual(UInt64.from(2)).toBoolean() &&
          getHeight(lastElementIdx.add(UInt64.one)).greaterThan(height).toBoolean()
        )
      ) {
        break;
      }
      // Allocate one new index for the parent node
      lastElementIdx = lastElementIdx.add(UInt64.one);

      // (Extra safeguard – should always be true here.)
      const hasEnoughPeaks = peaksLength.greaterThanOrEqual(UInt64.from(2));
      Provable.asProver(() => {
        if (!hasEnoughPeaks.toBoolean()) {
          throw new Error('Not enough elements in peaks to pop');
        }
      });

      // Get the last two peaks' hashes
      const rightHash = provablePeaks[Number(peaksLength.sub(UInt64.one).toBigInt())];
      const leftHash = provablePeaks[Number(peaksLength.sub(UInt64.from(2)).toBigInt())];
      const parentHash = Poseidon.hash([leftHash, rightHash]);
      
      // Write the parent hash to the hashes array at the new index
      this.hashes = Provable.witness(
        Provable.Array(Field, MAX_ELEMENTS),
        () => {
          let newHashes = [...this.hashes];
          newHashes[Number(lastElementIdx.toBigInt())] = parentHash;
          return newHashes;
        }
      );

      // Replace the last two peaks with the new parent hash
      provablePeaks = Provable.witness(Provable.Array(Field, MAX_PEAKS), () => {
        let newPeaks = [...provablePeaks];
        newPeaks[Number(peaksLength.sub(UInt64.from(2)).toBigInt())] = parentHash;
        newPeaks[Number(peaksLength.sub(UInt64.one).toBigInt())] = Field(0);
        return newPeaks;
      });
      
      peaksLength = peaksLength.sub(UInt64.one);
      height = height.add(UInt64.one);
    }

    // Update the MMR state with the new total number of nodes
    this.elementsCount = lastElementIdx;
    
    // Bag the (remaining) peaks to compute the final MMR root hash.
    const bag = this.bagThePeaks(
      provablePeaks.slice(0, Number(peaksLength.toBigInt()))
    );
    const rootHash = this.calculateRootHash(bag, lastElementIdx);
    this.rootHash = rootHash;

    this.leavesCount = this.leavesCount.add(UInt64.one);

    return {
      leavesCount: this.leavesCount,
      elementsCount: this.elementsCount,
      elementIndex: leafElementIndex,
      rootHash: this.rootHash,
    };
  }
  
  /**
   * Generates a proof of inclusion for a specific leaf.
   * @param {UInt64} leafIndex - The index of the leaf.
   * @returns {Proof} Inclusion proof.
   */
  getProof(leafIndex: UInt64): Proof {
    if (leafIndex.lessThan(UInt64.one).toBoolean()) {
      throw new Error('Index must be greater than 1');
    }

    const treeSize = this.elementsCount;
    if (leafIndex.greaterThan(treeSize).toBoolean()) {
      throw new Error('Index must be less than the tree size');
    }

    const peaks = findPeaks(treeSize);
    const siblings: UInt64[] = [];
    let index = leafIndex;

    // Replace the while loop with a for loop having a fixed bound.
    for (let i = 0; i < MAX_ELEMENTS; i++) {
      if (peaks.some((peak) => peak.equals(index).toBoolean())) {
        break;
      }
      const isRight = getHeight(index.add(UInt64.one))
        .equals(getHeight(index).add(UInt64.one))
        .toBoolean();
      const sib = isRight
        ? index.sub(siblingOffset(getHeight(index)))
        : index.add(siblingOffset(getHeight(index)));
      siblings.push(sib);
      index = isRight
        ? index.add(UInt64.one)
        : index.add(parentOffset(getHeight(index)));
    }

    // Create fixed‐size arrays with padding
    const siblingsHashes = new Array(MAX_PEAKS).fill(Field(0));
    const peaksHashes = new Array(MAX_PEAKS).fill(Field(0));

    // Fill arrays with actual values
    siblings.forEach((sib, i) => {
      siblingsHashes[i] = this.hashes[Number(sib.toBigInt())];
    });
    
    const peaksValues = this.retrievePeaksHashes(peaks);
    peaksValues.forEach((peak, i) => {
      peaksHashes[i] = peak;
    });

    return new Proof({
      elementIndex: leafIndex,
      elementHash: this.hashes[Number(leafIndex.toBigInt())],
      siblingsHashes,
      peaksHashes,
      siblingsLength: UInt64.from(siblings.length),
      peaksLength: UInt64.from(peaks.length),
      elementsCount: treeSize
    });
  }

  /**
   * Verifies the inclusion proof of a leaf in the MMR.
   * @param {Field} leaf - The leaf value.
   * @param {Proof} proof - The inclusion proof.
   * @returns {Bool} True if the proof is valid.
   */
  verifyProof(leaf: Field, proof: Proof): Bool {
    let { elementIndex, siblingsHashes, peaksHashes, elementsCount, siblingsLength, peaksLength } = proof;

    if (elementIndex.lessThan(UInt64.one).toBoolean()) {
      throw new Error('Index must be greater than or equal to 1');
    }
    if (elementIndex.greaterThan(elementsCount).toBoolean()) {
      throw new Error('Index must be in the tree');
    }

    let hash = leaf;

    // Process the sibling hashes (only up to the actual siblingsLength)
    for (let i = 0; i < MAX_PEAKS; i++) {
      const shouldProcess = UInt64.from(i).lessThan(siblingsLength);
      if (shouldProcess.toBoolean()) {
        const proofHash = siblingsHashes[i];
        const isRight = getHeight(elementIndex.add(UInt64.one))
          .equals(getHeight(elementIndex).add(UInt64.one))
          .toBoolean();
        elementIndex = isRight
          ? elementIndex.add(UInt64.one)
          : elementIndex.add(parentOffset(getHeight(elementIndex)));
        hash = isRight
          ? Poseidon.hash([proofHash, hash])
          : Poseidon.hash([hash, proofHash]);
      }
    }

    // Replace the corresponding peak hash with the reconstructed hash
    const validPeaks = peaksHashes.slice(0, Number(peaksLength.toBigInt()));
    const reconstructedPeaks = validPeaks.map(peakHash => 
      peakHash.equals(hash).toBoolean() ? hash : peakHash
    );

    const baggedHash = this.bagThePeaks(reconstructedPeaks);
    const recomputedRootHash = this.calculateRootHash(baggedHash, elementsCount);

    return recomputedRootHash.equals(this.rootHash);
  }

  /**
   * Preprocess the inclusion proof of a leaf in the MMR.
   * @param {Field} leaf - The leaf value.
   * @param {Proof} proof - The inclusion proof.
   * @returns {Field} The bagged peaks.
   */
  preprocess(leaf: Field, proof: Proof): Field {
    let { elementIndex, siblingsHashes, peaksHashes, elementsCount, siblingsLength, peaksLength } = proof;

    if (elementIndex.lessThan(UInt64.one).toBoolean()) {
      throw new Error('Index must be greater than or equal to 1');
    }
    if (elementIndex.greaterThan(elementsCount).toBoolean()) {
      throw new Error('Index must be in the tree');
    }

    let hash = leaf;

    // Process the sibling hashes (only up to the actual siblingsLength)
    for (let i = 0; i < MAX_PEAKS; i++) {
      const shouldProcess = UInt64.from(i).lessThan(siblingsLength);
      if (shouldProcess.toBoolean()) {
        const proofHash = siblingsHashes[i];
        const isRight = getHeight(elementIndex.add(UInt64.one))
          .equals(getHeight(elementIndex).add(UInt64.one))
          .toBoolean();
        elementIndex = isRight
          ? elementIndex.add(UInt64.one)
          : elementIndex.add(parentOffset(getHeight(elementIndex)));
        hash = isRight
          ? Poseidon.hash([proofHash, hash])
          : Poseidon.hash([hash, proofHash]);
      }
    }

    // Replace the corresponding peak hash with the reconstructed hash
    const validPeaks = peaksHashes.slice(0, Number(peaksLength.toBigInt()));
    const reconstructedPeaks = validPeaks.map(peakHash => 
      peakHash.equals(hash).toBoolean() ? hash : peakHash
    );

    const baggedHash = this.bagThePeaks(reconstructedPeaks);
    return baggedHash;
  }
  
  /**
   * Retrieves the current peaks of the MMR.
   * @returns {Field[]} Array of peak hashes.
   */
  getPeaks(): Field[] {
    const treeSize = this.elementsCount;
    const peaksIdxs = findPeaks(treeSize);
    const peaks = this.retrievePeaksHashes(peaksIdxs);
    return peaks;
  }

  /**
   * Bags the peaks to combine them into a single hash.
   * @param {Field[]} peaks - Array of peak hashes.
   * @returns {Field} Combined root hash.
   */
  bagThePeaks(peaks: Field[]): Field {
    if (peaks.length === 0) {
      return Field(0);
    } else if (peaks.length === 1) {
      return peaks[0];
    } else {
      let root0 = Poseidon.hash([
        peaks[peaks.length - 2],
        peaks[peaks.length - 1],
      ]);
      let root = peaks
        .slice(0, peaks.length - 2)
        .reverse()
        .reduce((prev, cur) => Poseidon.hash([cur, prev]), root0);
      return root;
    }
  }

  /**
   * Recalculates the root hash based on the current state.
   * @param {Field} bag - The combined peaks hash.
   * @param {UInt64} leafCount - The number of leaves (or total nodes).
   * @returns {Field} The new root hash.
   */
  calculateRootHash(bag: Field, leafCount: UInt64): Field {
    return Poseidon.hash([leafCount.value, bag]);
  }

  /**
   * Retrieves hashes for given peak indices.
   * @param {UInt64[]} peaksIndices - Indices of the peaks.
   * @returns {Field[]} Array of peak hashes.
   */
  retrievePeaksHashes(peaksIndices: UInt64[]): Field[] {
    let result = new Array(MAX_PEAKS).fill(Field(0));
    
    // Create a provable array for the result
    let provableResult = Provable.witness(
      Provable.Array(Field, MAX_PEAKS),
      () => {
        // For each peak index (the loop is bounded by MAX_PEAKS)
        for (let i = 0; i < peaksIndices.length; i++) {
          let peakIndex = peaksIndices[i];
          // Create a provable lookup for this peak's hash
          let peakHash = Provable.witness(Field, () => {
            return this.hashes[Number(peakIndex.toBigInt())];
          });
          result[i] = peakHash;
        }
        return result;
      }
    );

    return provableResult;
  }

  /**
   * Clears the MMR to reset its state.
   */
  clear() {
    this.leavesCount = UInt64.zero;
    this.elementsCount = UInt64.zero;
    let newHashes = this.hashes.slice();
    for (let i = 0; i < MAX_ELEMENTS; i++) {
      newHashes[i] = Field(0);
    }
    this.hashes = newHashes;
    this.rootHash = Field(0);
  }

  // Utility Functions

  count_ones(n: UInt64): UInt64 {
    let sum = UInt64.zero;
    let temp = n;
  
    for (let i = 0; i < 64; i++) {
      let lsbIsOne: Bool = temp.and(UInt64.one).equals(UInt64.one);
      sum = Provable.if(lsbIsOne, sum.add(UInt64.one), sum);
      let isPositive = temp.greaterThan(UInt64.zero);
      temp = Provable.if(isPositive, temp.div(UInt64.from(2)), temp);
    }
  
    return sum;
  }

  leaf_count_to_mmr_size(leafCount: UInt64): UInt64 {
    let twoTimes = leafCount.mul(UInt64.from(2));
    let ones = this.count_ones(leafCount);
    return twoTimes.sub(ones);
  }
}

// ---------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------

/**
 * Computes the peak positions for an MMR given its total node count.
 * Peels off the right–most perfect tree repeatedly.
 *
 * @param {UInt64} mmrSize - The total number of nodes in the MMR.
 * @returns {UInt64[]} An array of peak indices.
 */
function findPeaks(mmrSize: UInt64): UInt64[] {
  let peaks = new Array(MAX_PEAKS).fill(UInt64.zero);
  let peakCount = 0;
  let pos = mmrSize;

  for (let i = 0; i < MAX_PEAKS; i++) {
    const shouldContinue = pos.greaterThan(UInt64.zero);
    if (shouldContinue.toBoolean()) {
      let height = getHeight(pos);
      // Compute peakSize = 2^(height+1)-1
      let peakSize = pow2(height.add(UInt64.one)).sub(UInt64.one);
      
      // Store peak in reverse order (right to left)
      peaks[MAX_PEAKS - 1 - i] = pos;
      peakCount++;
      
      pos = pos.sub(peakSize);
    } else {
      break;
    }
  }

  // Return only the valid peaks (last peakCount elements)
  return peaks.slice(MAX_PEAKS - peakCount);
}

/**
 * Finds the index of the right sibling in the binary tree.
 * (No longer used by the new findPeaks, but kept for reference.)
 * @param {UInt64} elementIndex - The current index.
 * @returns {UInt64} The sibling index.
 */
function bintreeJumpRightSibling(elementIndex: UInt64): UInt64 {
  const height = getHeight(elementIndex);
  const shiftAmount = height.add(UInt64.one);
  const increment = pow2(shiftAmount).sub(UInt64.one);
  return elementIndex.add(increment);
}

/**
 * Moves down to the left child in the binary tree.
 * (No longer used by the new findPeaks, but kept for reference.)
 * @param {UInt64} elementIndex - The current index.
 * @returns {UInt64} The left child index.
 */
function bintreeMoveDownLeft(elementIndex: UInt64): UInt64 {
  let height = getHeight(elementIndex);
  let isHeightZero: Bool = height.equals(UInt64.zero);
  let decrement = pow2(height);
  let nextIndex = elementIndex.sub(decrement);
  let result = Provable.if(isHeightZero, UInt64.zero, nextIndex);
  return result;
}

/**
 * Determines the height of a node in the MMR.
 * @param {UInt64} elementIndex - The node index.
 * @returns {UInt64} The height.
 */
export function getHeight(elementIndex: UInt64): UInt64 {
  let h = elementIndex;
  for (let i = 0; i < 64; i++) {
    const isAllOnes: Bool = allOnes(h);
    const highestBit = pow2(bitLength(h).sub(UInt64.one));
    const newH = h.sub(highestBit.sub(UInt64.one));
    h = Provable.if(isAllOnes.not(), newH, h);
  }
  return bitLength(h).sub(UInt64.one);
}

/**
 * Checks if a number's binary representation consists of all ones.
 * @param {UInt64} num - The number to check.
 * @returns {Bool} True if all ones.
 */
export function allOnes(num: UInt64): Bool {
  const ones = pow2(bitLength(num)).sub(UInt64.one);
  return num.equals(ones);
}

/**
 * Calculates the number of bits needed to represent num.
 * @param {UInt64} num - The number.
 * @returns {UInt64} The bit length.
 */
export function bitLength(num: UInt64): UInt64 {
  let length = UInt64.zero;
  let temp = num;
  for (let i = 0; i < 64; i++) {
    let isPositive = temp.greaterThan(UInt64.zero);
    length = Provable.if(isPositive, length.add(UInt64.one), length);
    temp = Provable.if(isPositive, temp.div(UInt64.from(2)), temp);
  }
  return length;
}

/**
 * Computes exponents of 2 efficiently.
 * @param {UInt64} exponent - The exponent.
 * @returns {UInt64} The result of 2^exponent.
 */
export function pow2(exponent: UInt64): UInt64 {
  let result = UInt64.one;
  let exp = exponent.add(UInt64.one);
  const two = UInt64.from(2);
  for (let i = 0; i < 64; i++) {
    const cond: Bool = exp.greaterThan(UInt64.one);
    result = Provable.if(cond, result.mul(two), result);
    exp = Provable.if(cond, exp.sub(UInt64.one), exp);
  }
  return result;
}

/**
 * Computes the sibling offset based on the height.
 * @param {UInt64} height - The height.
 * @returns {UInt64} The sibling offset.
 */
function siblingOffset(height: UInt64): UInt64 {
  return pow2(height);
}

/**
 * Computes the parent offset based on the height.
 * @param {UInt64} height - The height.
 * @returns {UInt64} The parent offset.
 */
function parentOffset(height: UInt64): UInt64 {
  return pow2(height.add(UInt64.one)).sub(UInt64.one);
}
