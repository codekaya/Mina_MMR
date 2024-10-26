// Import necessary modules from o1.js
import { Field, UInt64, Poseidon } from 'o1js';

// Helper Functions

// Calculate the height of a node in the MMR
function getHeight(elementIndex: UInt64) {
  let h = elementIndex;
  while (!allOnes(h).toBoolean()) {
    const highestBit = pow2(bitLength(h).sub(UInt64.one));
    h = h.sub(highestBit.sub(UInt64.one));
  }
  return bitLength(h).sub(UInt64.one);
}

// Check if a number consists of all ones in binary representation
function allOnes(num) {
  const ones = pow2(bitLength(num)).sub(UInt64.one);
  return num.equals(ones);
}

// Calculate the bit length of a UInt64 number
function bitLength(num) {
  let length = UInt64.zero;
  let temp = num;

  while (temp.greaterThan(UInt64.zero).toBoolean()) {
    temp = temp.div(UInt64.from(2));
    length = length.add(UInt64.one);
  }

  return length;
}

// Calculate 2 raised to the power of exponent
function pow2(exponent) {
  let result = UInt64.one;
  const two = UInt64.from(2);
  let exp = exponent;

  while (exp.greaterThan(UInt64.zero).toBoolean()) {
    result = result.mul(two);
    exp = exp.sub(UInt64.one);
  }

  return result;
}

// Move to the right sibling in the binary tree
function bintreeJumpRightSibling(elementIndex) {
  const height = getHeight(elementIndex);
  const shiftAmount = height.add(UInt64.one);
  const increment = pow2(shiftAmount).sub(UInt64.one);
  return elementIndex.add(increment);
}

// Move down to the left child in the binary tree
function bintreeMoveDownLeft(elementIndex) {
  const height = getHeight(elementIndex);
  if (height.equals(UInt64.zero).toBoolean()) {
    return UInt64.zero;
  }
  const decrement = pow2(height);
  return elementIndex.sub(decrement);
}

// Find the peak positions in the MMR given the element count
function findPeaks(elementCount) {
  const peaks = [];
  if (elementCount.equals(UInt64.zero)) {
    return peaks;
  }

  let top = UInt64.one;
  while (top.sub(UInt64.one).lessThanOrEqual(elementCount).toBoolean()) {
    top = top.mul(UInt64.from(2));
  }
  top = top.div(UInt64.from(2)).sub(UInt64.one);

  if (top.equals(UInt64.zero).toBoolean()) {
    peaks.push(UInt64.one);
    return peaks;
  }

  let peak = top;
  peaks.push(peak);
  let outer = true;

  while (outer) {
    peak = bintreeJumpRightSibling(peak);

    while (peak.greaterThan(elementCount).toBoolean()) {
      peak = bintreeMoveDownLeft(peak);
      if (peak.equals(UInt64.zero).toBoolean()) {
        outer = false;
        break;
      }
    }

    if (outer) {
      peaks.push(peak);
    }
  }

  return peaks;
}

// MMR Class Definition
class MMR {
  constructor() {
    this.elementsCount = UInt64.zero;
    this.leavesCount = UInt64.zero;
    this.rootHash = Field.zero;
    this.hashes = new Map(); // Stores hashes with their indices as keys
    this.hasher = Poseidon; // Using Poseidon hash function
  }

  // Check if the element size is valid for hashing
  isElementSizeValid(value) {
    // For Field elements in o1.js, this is generally always true
    return true;
  }

  // Retrieve hashes for the given peaks
  retrievePeaksHashes(peaksIndices) {
    const peaksHashes = [];
    for (const index of peaksIndices) {
      const hash = this.hashes.get(index.toString());
      if (hash) {
        peaksHashes.push(hash);
      } else {
        // Handle missing hash (should not happen in a consistent MMR)
        peaksHashes.push(Field.zero);
      }
    }
    return peaksHashes;
  }

  // Bag the peaks (combine them into a single value)
  bagThePeaks() {
    // In a full implementation, this would involve combining peaks appropriately
    // For simplicity, we'll return the current peaks as is
    return this.peaks;
  }

  // Calculate the root hash from the bagged peaks
  calculateRootHash(bag, lastElementIdx) {
    let rootHash = bag[0];
    for (let i = 1; i < bag.length; i++) {
      rootHash = this.hasher.hash([rootHash, bag[i]]);
    }
    return rootHash;
  }

  // Append a new value to the MMR
  append(value) {
    if (!this.isElementSizeValid(value)) {
      throw new Error("Element size is too big to hash with this hasher");
    }

    const elementsCount = this.elementsCount;
    const peaksIndices = findPeaks(elementsCount);
    const peaks = this.retrievePeaksHashes(peaksIndices);

    // Increment elementsCount
    this.elementsCount = this.elementsCount.add(UInt64.one);
    let lastElementIdx = this.elementsCount;

    const leafElementIndex = lastElementIdx;

    // Store the new value at the last index
    this.hashes.set(lastElementIdx.toString(), value);

    // Add the new value to peaks
    peaks.push(value);

    let height = UInt64.zero;

    // Loop to update peaks and compute parent hashes
    while (getHeight(lastElementIdx.add(UInt64.one)).greaterThan(height).toBoolean()) {
      lastElementIdx = lastElementIdx.add(UInt64.one);

      const rightHash = peaks.pop();
      const leftHash = peaks.pop();

      const parentHash = this.hasher.hash([leftHash, rightHash]);
      this.hashes.set(lastElementIdx.toString(), parentHash);
      peaks.push(parentHash);

      height = height.add(UInt64.one);
    }

    // Update elementsCount with the last index used
    this.elementsCount = lastElementIdx;

    // Bag the peaks to compute the final root hash
    this.peaks = peaks; // Store the updated peaks
    const bag = this.bagThePeaks();
    const rootHash = this.calculateRootHash(bag, lastElementIdx);
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
}

// Example Usage

// Initialize the MMR
const mmr = new MMR();

// Append a new value
const newValue = Field.random();
const result = mmr.append(newValue);

// Output the result
console.log('Result of append operation:', {
  leavesCount: result.leavesCount.toString(),
  elementsCount: result.elementsCount.toString(),
  elementIndex: result.elementIndex.toString(),
  rootHash: result.rootHash.toString(),
});
