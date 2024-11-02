import { 
    Field,
    SmartContract,
    UInt64,Struct, 
    Poseidon, 
    state, 
    State, 
    method ,
    Circuit, 
    Bool,
    Provable
   } from 'o1js';
 

     /**
   * Proof structure for inclusion proofs.
   */
  class Proof extends Struct({
    elementIndex: UInt64,
    elementHash: Field,
    siblingsHashes: [Field],
    peaksHashes: [Field],
    elementsCount: UInt64,
  }) {}
 /*
 
 Struct MMR
 leavesCount
 elementsCount
 hashes
 RootHash
 
 
 Functions:
 append(data : Field) 
 GetProof
 VerifyProof
 GetProofs
 VerifyProofs
 GetPeaks
 BagThePeaks
 CalculateRootHash
 RetrievePeaksHashes
 Clear
 
 Utility Functions:
 count_ones(n: number)
 findPeaks(elementCount: UInt64): UInt64[]
 bintreeJumpRightSibling(elementIndex: UInt64): UInt64
 bintreeMoveDownLeft(elementIndex: UInt64): UInt64
 getHeight(elementIndex: UInt64): UInt64
 allOnes(num: UInt64): Bool
 pow2(exponent: UInt64): UInt64
 bitLength(num: UInt64): UInt64
 mapLeafIndexToElementIndex(leafIndex: number)
 mapElementIndexToLeafIndex(elementIndex: number)
 

 */
 
 
 const MAX_ELEMENTS = 2097151;  // 2,097,151 = 2^(h+1)-1   max_height=20
 const MAX_LEAFS = 1048576 //2^10  = 1,048,576
 
 /**
  * Merkle Mountain Range class.
  */
  class MerkleMountainRange extends Struct({
   leavesCount : UInt64,
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
       rootHash: new Field(0),
     });
   }
 
   /**
    * Append a new leaf to the MMR.
    * @param {Field} data - The data to add to the MMR.
    */
    append(value: Field): {
      leavesCount: UInt64;
      elementsCount: UInt64;
      elementIndex: UInt64;
      rootHash: Field;
    } {
      // Increment elementsCount
      let elementsCount = this.elementsCount;
      const peaksIndices = findPeaks(elementsCount);
      let peaks = this.retrievePeaksHashes(peaksIndices);
    
      // Increment elementsCount
      elementsCount = elementsCount.add(UInt64.one);
      let lastElementIdx = elementsCount;
    
      const leafElementIndex = lastElementIdx;
    
      // Store the new value at the last index
      this.hashes[Number(lastElementIdx.toBigInt())] = value;
    
      // Add the new value to peaks
      peaks.push(value);
    
      let height = UInt64.zero;
    
      // Loop to update peaks and compute parent hashes
      while (
        getHeight(lastElementIdx.add(UInt64.one))
          .greaterThan(height)
          .toBoolean()
      ) {
        lastElementIdx = lastElementIdx.add(UInt64.one);
    
        // Ensure peaks has enough elements
        if (peaks.length < 2) {
          throw new Error('Not enough elements in peaks to pop');
        }
    
        const rightHash = peaks.pop()!;
        const leftHash = peaks.pop()!;
    
        const parentHash = Poseidon.hash([leftHash, rightHash]);
        this.hashes[Number(lastElementIdx.toBigInt())] = parentHash;
        peaks.push(parentHash);
    
        height = height.add(UInt64.one);
      }
    
      // Update elementsCount with the last index used
      this.elementsCount = lastElementIdx;
    
      // Bag the peaks to compute the final root hash
      const bag = this.bagThePeaks(peaks);
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
  //   append(data : Field) {
  //    // Validate input
  //    if (!(data instanceof Field)) {
  //      throw new Error('Data must be an instance of Field.');
  //    }
 
  //    // Increment leaves count
  //    this.leavesCount = this.leavesCount.add(1);
 
  //    // Hash the data to create the leaf hash
  //    const leafHash = Poseidon.hash([data]);
 
  //    // Increment elements count and store the leaf hash
  //    this.elementsCount = this.elementsCount.add(1);
  //    const elementIndex = this.elementsCount.toBigInt();
  //    this.hashes[Number(elementIndex)] =leafHash;
  //    console.log(leafHash)
  //    return leafHash;
  //    // Build the peaks and update the MMR
  //    //this._buildPeaks(leafHash, elementIndex);
 
  //    // Update the root hash
  //    //this.rootHash = this._bagPeaks();
  //  }
 
//    append(value) {
//     if (!this.isElementSizeValid(value)) {
//       throw new Error("Element size is too big to hash with this hasher");
//     }

//     const elementsCount = this.elementsCount;
//     const peaksIndices = findPeaks(elementsCount);
//     const peaks = this.retrievePeaksHashes(peaksIndices);

//     // Increment elementsCount
//     this.elementsCount = this.elementsCount.add(UInt64.one);
//     let lastElementIdx = this.elementsCount;

//     const leafElementIndex = lastElementIdx;

//     // Store the new value at the last index
//     this.hashes.set(lastElementIdx.toString(), value);

//     // Add the new value to peaks
//     peaks.push(value);

//     let height = UInt64.zero;

//     // Loop to update peaks and compute parent hashes
//     while (getHeight(lastElementIdx.add(UInt64.one)).greaterThan(height).toBoolean()) {
//       lastElementIdx = lastElementIdx.add(UInt64.one);

//       const rightHash = peaks.pop();
//       const leftHash = peaks.pop();

//       const parentHash = this.hasher.hash([leftHash, rightHash]);
//       this.hashes.set(lastElementIdx.toString(), parentHash);
//       peaks.push(parentHash);

//       height = height.add(UInt64.one);
//     }

//     // Update elementsCount with the last index used
//     this.elementsCount = lastElementIdx;

//     // Bag the peaks to compute the final root hash
//     this.peaks = peaks; // Store the updated peaks
//     const bag = this.bagThePeaks();
//     const rootHash = this.calculateRootHash(bag, lastElementIdx);
//     this.rootHash = rootHash;

//     // Increment leavesCount
//     this.leavesCount = this.leavesCount.add(UInt64.one);

//     // Return the updated counts and root hash
//     return {
//       leavesCount: this.leavesCount,
//       elementsCount: this.elementsCount,
//       elementIndex: leafElementIndex,
//       rootHash: this.rootHash,
//     };
//   }

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

    while (!peaks.some((peak) => peak.equals(index).toBoolean())) {
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

    const peaksHashes = this.retrievePeaksHashes(peaks);
    const siblingsHashes = siblings.map(
      (sib) => this.hashes[Number(sib.toBigInt())]
    );

    const elementHash = this.hashes[Number(leafIndex.toBigInt())];

    return new Proof({
      elementIndex: leafIndex,
      elementHash: elementHash,
      siblingsHashes: siblingsHashes,
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
    let { elementIndex, siblingsHashes, peaksHashes, elementsCount } = proof;

    if (elementIndex.lessThan(UInt64.one).toBoolean()) {
      throw new Error('Index must be greater than 1');
    }
    if (elementIndex.greaterThan(elementsCount).toBoolean()) {
      throw new Error('Index must be in the tree');
    }

    let hash = leaf;

    for (let i = 0; i < siblingsHashes.length; i++) {
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

    // Check if hash is in peaksHashes
    const isInPeaks = peaksHashes.some((peakHash) =>
      peakHash.equals(hash).toBoolean()
    );
    return new Bool(isInPeaks);
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
   * @param {UInt64} leafCount - The number of leaves.
   * @returns {Field} The new root hash.
   */
  calculateRootHash(bag: Field, leafCount: UInt64): Field {
    return Poseidon.hash([Field(leafCount.toBigInt()), bag]);
  }

  /**
     * Retrieves hashes for given peak indices.
     * @param {UInt64[]} peaksIndices - Indices of the peaks.
     * @returns {Field[]} Array of peak hashes.
     */
   retrievePeaksHashes(peaksIndices: UInt64[]): Field[] {
    return peaksIndices.map(
      (index) => this.hashes[Number(index.toBigInt())]
    );
  }

/**
     * Clears the MMR to reset its state.
     */
 clear() {
  this.leavesCount = UInt64.zero;
  this.elementsCount = UInt64.zero;
  this.hashes.fill(Field(0));
  this.rootHash = Field(0);
}

   count_ones(n: number) {
     let sum = 0;
     while (n) {
         sum++;
         n &= n - 1;
     }
     return sum;
   }
 
   leaf_count_to_mmr_size(leaf_count: number) {
     return 2 * leaf_count - this.count_ones(leaf_count);
   }

}
//-------FIND PEAKS---------------
/**
 * Finds the peaks in a Merkle Mountain Range (MMR) given the element count.
 * @param elementCount The number of elements in the MMR.
 * @returns An array of peak positions.
 */
function findPeaks(elementCount: UInt64): UInt64[] {
  if (elementCount.equals(UInt64.zero).toBoolean()) return [];

  const peaks: UInt64[] = [];
  let top = UInt64.one;

  // Find the largest power of 2 <= elementCount
  while (top.sub(UInt64.one).lessThanOrEqual(elementCount).toBoolean()) {
    top = top.mul(UInt64.from(2));
  }
  top = top.div(UInt64.from(2)).sub(UInt64.one);

  if (top.equals(UInt64.zero).toBoolean()) return [UInt64.one];

  // Initialize with the first peak
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

    if (outer) peaks.push(peak);
  }

  return peaks;
}

// Helper functions

function bintreeJumpRightSibling(elementIndex: UInt64): UInt64 {
  const height = getHeight(elementIndex);
  const shiftAmount = height.add(UInt64.one);
  const increment = pow2(shiftAmount).sub(UInt64.one);
  return elementIndex.add(increment);
}

function bintreeMoveDownLeft(elementIndex: UInt64): UInt64 {
  const height = getHeight(elementIndex);
  if (height.equals(UInt64.zero).toBoolean()) {
    return UInt64.zero;
  }
  const decrement = pow2(height);
  return elementIndex.sub(decrement);
}

function getHeight(elementIndex: UInt64): UInt64 {
  let h = elementIndex;
  while (allOnes(h).not().toBoolean()) {
    const highestBit = pow2(bitLength(h).sub(UInt64.one));
    h = h.sub(highestBit.sub(UInt64.one));
  }
  return bitLength(h).sub(UInt64.one);
}

function allOnes(num: UInt64): Bool {
  const ones = pow2(bitLength(num)).sub(UInt64.one);
  return num.equals(ones);
}

function bitLength(num: UInt64): UInt64 {
  // Compute the bit length of num
  let length = UInt64.zero;
  let temp = num;

  while (temp.greaterThan(UInt64.zero).toBoolean()) {
    temp = temp.div(UInt64.from(2));
    length = length.add(UInt64.one);
  }

  return length;
}

function pow2(exponent: UInt64): UInt64 {
  // Compute 2^exponent
  let result = UInt64.one;
  const two = UInt64.from(2);
  let exp = exponent;

  while (exp.greaterThan(UInt64.zero).toBoolean()) {
    result = result.mul(two);
    exp = exp.sub(UInt64.one);
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


//----------------------------------------

 
 
 export class Mmr extends SmartContract {
   @state(Field) num = State<Field>();
   @state(Field) leavesCount = State<Field>();
 
   init() {
     super.init();
     this.num.set(Field(2));
     const initialMMR = new MerkleMountainRange();
     //this.num.set(initialMMR.append(Field(1)));
     const a = initialMMR.append(Field(1))
     const leafHash = Poseidon.hash([Field(1)]);
     //console.log("leaf", leafHash);
     //console.log("a", a);
     // if(leafHash==a){
     //   this.num.set(Field(1));
     //   console.log("selamm")
     // }
     //const x = Provable.if(new Bool(leafHash.equals(a)), Field(1), Field(5));
     console.log(this.num, "syao");
     //console.log(x);
     this.num.set(Field(1));

     // Example usage
    const elementCount = UInt64.from(22); // example element count
    const peaks = findPeaks(elementCount);
    console.log('Peaks:', peaks.map((p) => p.toString())); // Outputs the peak positions in the MMR
   }
 
   @method async update() {
     const currentState = this.num.getAndRequireEquals();
     const newState = currentState.add(2);
     this.num.set(newState);
   }
 }
 