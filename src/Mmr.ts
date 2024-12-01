import {
  Field,
  SmartContract,
  UInt64,
  UInt32,
  Struct,
  Poseidon,
  state,
  State,
  method,
  Circuit,
  Bool,
  Provable,
} from 'o1js';

const MAX_ELEMENTS = 2097151; // 2,097,151 = 2^(h+1)-1   max_height=20
const MAX_HEIGHT = 20;
const MAX_PEAKS = MAX_HEIGHT + 1;

/**
 * Proof structure for inclusion proofs.
 */
export class Proof extends Struct({
  elementIndex: UInt64,
  elementHash: Field,
  siblingsHashes: [Field, MAX_HEIGHT],
  peaksHashes: [Field, MAX_PEAKS],
  elementsCount: UInt64,
}) {}

/**
 * Merkle Mountain Range class.
 */
export class MerkleMountainRange extends Struct({
  leavesCount: UInt64,
  elementsCount: UInt64,
  hashes: [Field, MAX_ELEMENTS],
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

  append(value: Field): {
    leavesCount: UInt64;
    elementsCount: UInt64;
    elementIndex: UInt64;
    rootHash: Field;
  } {
    // Initialize peaks
    let peaks: Field[] = Array(MAX_PEAKS).fill(Field(0));
    let peaksCount = UInt32.zero;

    // Retrieve current peaks
    const peaksIndices = findPeaks(this.elementsCount);
    for (let i = 0; i < MAX_PEAKS; i++) {
      peaks[i] = Provable.if(
        peaksIndices.isSet(i),
        this.hashes[peaksIndices.getValue(i)],
        Field(0)
      );
    }
    peaksCount = UInt32.from(peaksIndices.count);

    // Increment elementsCount
    this.elementsCount = this.elementsCount.add(UInt64.one);
    const leafElementIndex = this.elementsCount.sub(UInt64.one);

    // Update hashes with the new value
    this.hashes = this.updateHashes(
      this.hashes,
      leafElementIndex,
      value
    );

    // Add the new value to peaks
    peaks[Number(peaksCount.toConstant())] = value;
    peaksCount = peaksCount.add(UInt32.one);

    // Loop to update peaks and compute parent hashes
    for (let h = 0; h < MAX_HEIGHT; h++) {
      const condition = this.shouldCombinePeaks(peaksCount);
      const leftHash = peaks[Number(peaksCount.sub(UInt32.from(2)).toConstant())];
      const rightHash = peaks[Number(peaksCount.sub(UInt32.one).toConstant())];
      const parentHash = Poseidon.hash([leftHash, rightHash]);

      // Update hashes
      this.hashes = this.updateHashes(
        this.hashes,
        this.elementsCount,
        parentHash
      );

      // Update peaks conditionally
      peaks[Number(peaksCount.sub(UInt32.from(2)).toConstant())] = Provable.if(
        condition,
        parentHash,
        peaks[Number(peaksCount.sub(UInt32.from(2)).toConstant())]
      );
      peaksCount = Provable.if(
        condition,
        peaksCount.sub(UInt32.one),
        peaksCount
      );
    }

    // Bag the peaks to compute the final root hash
    const bag = this.bagThePeaks(peaks, peaksCount);
    const rootHash = this.calculateRootHash(bag, this.elementsCount);
    this.rootHash = rootHash;

    // Increment leavesCount
    this.leavesCount = this.leavesCount.add(UInt64.one);

    // Return the updated counts and root hash
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
    leafIndex.assertGreaterThanOrEqual(UInt64.zero);
    leafIndex.assertLessThan(this.elementsCount);

    const treeSize = this.elementsCount;

    const peaks = findPeaks(treeSize);
    const siblings: Field[] = Array(MAX_HEIGHT).fill(Field(0));
    let siblingsCount = UInt32.zero;
    let index = leafIndex;

    for (let i = 0; i < MAX_HEIGHT; i++) {
      const isPeak = peaks.contains(index);
      const continueLoop = isPeak.not();

      const height = getHeight(index);
      const siblingIndex = Provable.if(
        this.isRightNode(index),
        index.sub(siblingOffset(height)),
        index.add(siblingOffset(height))
      );

      // Retrieve sibling hash
      const siblingHash = this.hashes[Number(siblingIndex.toBigInt())];
      siblings[i] = Provable.if(continueLoop, siblingHash, Field(0));
      siblingsCount = Provable.if(
        continueLoop,
        siblingsCount.add(UInt32.one),
        siblingsCount
      );

      // Update index for next iteration
      index = Provable.if(
        this.isRightNode(index),
        index.add(UInt64.one),
        index.add(parentOffset(height))
      );
    }

    // Prepare peaks hashes
    const peaksHashes = Array(MAX_PEAKS).fill(Field(0));
    for (let i = 0; i < MAX_PEAKS; i++) {
      peaksHashes[i] = Provable.if(
        peaks.isSet(i),
        this.hashes[peaks.getValue(i)],
        Field(0)
      );
    }

    const elementHash = this.hashes[Number(leafIndex.toBigInt())];

    return new Proof({
      elementIndex: leafIndex,
      elementHash: elementHash,
      siblingsHashes: siblings,
      peaksHashes: peaksHashes,
      elementsCount: treeSize,
    });
  }

  /**
   * Verifies the inclusion proof of a leaf in the MMR.
   * @param {Field} leaf - The leaf value.
   * @param {Proof} proof - The inclusion proof.
   * @returns {Bool} True if the proof is valid.
   */
  verifyProof(leaf: Field, proof: Proof): Bool {
    const { elementIndex, siblingsHashes, peaksHashes, elementsCount } = proof;

    elementIndex.assertGreaterThanOrEqual(UInt64.zero);
    elementIndex.assertLessThan(elementsCount);

    let hash = leaf;
    let index = elementIndex;

    // Reconstruct the hash up to the peak
    for (let i = 0; i < MAX_HEIGHT; i++) {
      const siblingHash = siblingsHashes[i];
      const height = getHeight(index);
      const isRight = this.isRightNode(index);

      index = Provable.if(
        isRight,
        index.add(UInt64.one),
        index.add(parentOffset(height))
      );

      hash = Provable.if(
        isRight,
        Poseidon.hash([siblingHash, hash]),
        Poseidon.hash([hash, siblingHash])
      );
    }

    // Compare reconstructed hash with peaks
    let isValid = Bool(false);
    for (let i = 0; i < MAX_PEAKS; i++) {
      const peakHash = peaksHashes[i];
      isValid = isValid.or(peakHash.equals(hash));
    }

    // Recompute the root hash
    const baggedHash = this.bagThePeaks(peaksHashes, UInt32.from(MAX_PEAKS));
    const recomputedRootHash = this.calculateRootHash(baggedHash, elementsCount);

    // Compare the recomputed root hash with the MMR's root hash
    return isValid.and(recomputedRootHash.equals(this.rootHash));
  }

  /**
   * Updates hashes array conditionally.
   */
  updateHashes(hashes: Field[], index: UInt64, value: Field): Field[] {
    const newHashes = hashes.slice();
    for (let i = 0; i < MAX_ELEMENTS; i++) {
      const condition = index.equals(UInt64.from(i));
      newHashes[i] = Provable.if(condition, value, hashes[i]);
    }
    return newHashes;
  }

  /**
   * Determines if a node is a right node.
   */
  isRightNode(index: UInt64): Bool {
    const height = getHeight(index);
    const leftSiblingIndex = index.sub(UInt64.one);
    const leftSiblingHeight = getHeight(leftSiblingIndex);
    return leftSiblingHeight.equals(height);
  }

  /**
   * Determines if peaks should be combined.
   */
  shouldCombinePeaks(peaksCount: UInt32): Bool {
    // Since we have a fixed MAX_PEAKS, we can determine the condition based on peaksCount
    return peaksCount.greaterThanOrEqual(UInt32.from(2));
  }

  /**
   * Bags the peaks to combine them into a single hash.
   * @param {Field[]} peaks - Array of peak hashes.
   * @param {UInt32} peaksCount - Number of peaks.
   * @returns {Field} Combined root hash.
   */
  bagThePeaks(peaks: Field[], peaksCount: UInt32): Field {
    let root = peaks[0];
    for (let i = 1; i < MAX_PEAKS; i++) {
      const inRange = peaksCount.greaterThan(UInt32.from(i));
      root = Provable.if(
        inRange,
        Poseidon.hash([peaks[i], root]),
        root
      );
    }
    return root;
  }

  /**
   * Recalculates the root hash based on the current state.
   * @param {Field} bag - The combined peaks hash.
   * @param {UInt64} elementsCount - The number of elements.
   * @returns {Field} The new root hash.
   */
  calculateRootHash(bag: Field, elementsCount: UInt64): Field {
    return Poseidon.hash([...elementsCount.toFields(), bag]);
  }

  /**
   * Clears the MMR to reset its state.
   */
   clear() {
    // Reset leavesCount and elementsCount
    this.leavesCount = UInt64.zero;
    this.elementsCount = UInt64.zero;
    this.rootHash = Field(0);

    // Reset hashes array
    // Due to circuit constraints, we cannot loop over large arrays.
    // We'll create a new array filled with zeros and assign it.
    // However, in practice, this is not efficient and may not be feasible.
    // For circuits, it's better to avoid such operations on large arrays.

    // Create a new hashes array with zeros
    const zeroField = Field(0);
    const newHashes = this.hashes.map(() => zeroField);

    // Assign the new hashes array
    this.hashes = newHashes;
  }
}

/**
 * Finds the peaks in a Merkle Mountain Range (MMR) given the element count.
 * Returns a fixed-size object with methods to check if an index is set and to get values.
 */
function findPeaks(elementCount: UInt64): {
  isSet: (index: number) => Bool;
  getValue: (index: number) => number;
  count: number;
  contains: (index: UInt64) => Bool;
} {
  const peaksIndices: number[] = [];
  let remaining = elementCount.toBigInt();
  for (let height = MAX_HEIGHT; height >= 0; height--) {
    const peakSize = (1n << BigInt(height + 1)) - 1n;
    if (remaining >= peakSize) {
      peaksIndices.push(Number(remaining - 1n));
      remaining -= peakSize;
    }
  }

  return {
    isSet: (index: number) => Bool(index < peaksIndices.length),
    getValue: (index: number) => peaksIndices[index] || 0,
    count: peaksIndices.length,
    contains: (index: UInt64) => {
      let isContained = Bool(false);
      for (let i = 0; i < peaksIndices.length; i++) {
        isContained = isContained.or(index.equals(UInt64.from(peaksIndices[i])));
      }
      return isContained;
    },
  };
}

/**
 * Calculates the bit length of a number.
 * @param {UInt64} num - The number.
 * @returns {UInt32} The bit length.
 */
 function bitLength(num: UInt64): UInt32 {
  const bits = num.value.toBits(); // bits[0] is LSB
  let length = UInt32.zero;
  let foundOne = Bool(false);
  for (let i = 63; i >= 0; i--) {
    const bit = bits[i];
    foundOne = foundOne.or(bit);
    length = Provable.if(foundOne.and(bit), UInt32.from(i + 1), length);
  }
  return length;
}


/**
 * Checks if a number's binary representation consists of all ones.
 * @param {UInt64} num - The number to check.
 * @returns {Bool} True if all ones.
 */
 function allOnes(num: UInt64): Bool {
  const bits = num.value.toBits(); // bits[0] is LSB
  let isAllOnes = Bool(true);
  for (let i = 0; i < 64; i++) {
    isAllOnes = isAllOnes.and(bits[i]);
  }
  return isAllOnes;
}

 /**
 * Determines the height of a node in the MMR.
 * @param {UInt64} index - The node index.
 * @returns {UInt32} The height.
 */
function getHeight(index: UInt64): UInt32 {
  // Compute the number of trailing zeros in index + 1
  const indexPlusOne = index.add(UInt64.one);
  const bits = indexPlusOne.value.toBits(); // bits[0] is LSB
  let height = UInt32.zero;
  let foundOne = Bool(false);
  for (let i = 0; i < 64; i++) {
    const bit = bits[i];
    const condition = bit.and(foundOne.not());
    height = Provable.if(condition, UInt32.from(i), height);
    foundOne = foundOne.or(bit);
  }
  return height;
}

/**
 * Computes the sibling offset based on the height.
 * @param {UInt32} height - The height.
 * @returns {UInt64} The sibling offset.
 */
function siblingOffset(height: UInt32): UInt64 {
  return pow2(height);
}

/**
 * Computes the parent offset based on the height.
 * @param {UInt32} height - The height.
 * @returns {UInt64} The parent offset.
 */
function parentOffset(height: UInt32): UInt64 {
  return pow2(height.add(UInt32.one)).sub(UInt64.one);
}

/**
 * Computes exponents of 2 up to MAX_HEIGHT efficiently.
 * @param {UInt32} exponent - The exponent.
 * @returns {UInt64} The result of 2^exponent.
 */
function pow2(exponent: UInt32): UInt64 {
  const pow2Values: UInt64[] = [
    UInt64.from(1),          // 2^0
    UInt64.from(2),          // 2^1
    UInt64.from(4),          // 2^2
    UInt64.from(8),          // 2^3
    UInt64.from(16),         // 2^4
    UInt64.from(32),         // 2^5
    UInt64.from(64),         // 2^6
    UInt64.from(128),        // 2^7
    UInt64.from(256),        // 2^8
    UInt64.from(512),        // 2^9
    UInt64.from(1024),       // 2^10
    UInt64.from(2048),       // 2^11
    UInt64.from(4096),       // 2^12
    UInt64.from(8192),       // 2^13
    UInt64.from(16384),      // 2^14
    UInt64.from(32768),      // 2^15
    UInt64.from(65536),      // 2^16
    UInt64.from(131072),     // 2^17
    UInt64.from(262144),     // 2^18
    UInt64.from(524288),     // 2^19
    UInt64.from(1048576),    // 2^20
  ];
  let result = UInt64.zero;
  for (let i = 0; i <= MAX_HEIGHT; i++) {
    const isMatch = exponent.equals(UInt32.from(i));
    result = Provable.if(isMatch, pow2Values[i], result);
  }
  return result;
}
