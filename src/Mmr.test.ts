// mmr.test.ts

import {
  Field,
  UInt64,
  Poseidon,
  Provable,
} from 'o1js';
import { MerkleMountainRange, Proof } from './Mmr'; // Adjust the import path

let proofsEnabled = false;

beforeAll(async () => {
  if (proofsEnabled){};
});

// afterAll(() => {
//   setTimeout(() => shutdown(), 0);
// });

describe('MerkleMountainRange Tests', () => {
  it('should initialize an empty MMR', () => {
    const mmr = new MerkleMountainRange();
    expect(mmr.leavesCount).toEqual(UInt64.zero);
    expect(mmr.elementsCount).toEqual(UInt64.zero);
    expect(mmr.rootHash).toEqual(Field(0));
  });

  it('should append elements and update root hash', () => {
    const mmr = new MerkleMountainRange();
    const values = [Field(1), Field(2), Field(3), Field(1), Field(2), Field(3)];

    values.forEach((value) => {
      const { rootHash } = mmr.append(value);
      expect(rootHash).toBeInstanceOf(Field);
    });

    Provable.runAndCheck(() => {
      const mmr2 = new MerkleMountainRange();
      mmr2.append(Field(5));
      // Other operations
    });

    expect(mmr.leavesCount).toEqual(UInt64.from(6));
    expect(mmr.elementsCount.greaterThan(UInt64.from(6)).toBoolean()).toBe(true);
    expect(mmr.rootHash).toBeInstanceOf(Field);
  });

  // it('should generate and verify a proof for an element', () => {
  //   const mmr = new MerkleMountainRange();
  //   const values = [Field(10), Field(20),Field(30),Field(40)];

  //   values.forEach((value) => {
  //     mmr.append(value);
  //   });

  //   const leafIndex = UInt64.from(2);
  //   const proof = mmr.getProof(leafIndex);
  //   console.log("leafindex", leafIndex, "proof", proof, "vales" , values[1]);
  //   // Verify the proof
  //   const isValid = mmr.verifyProof(values[1], proof);
  //   expect(isValid.toBoolean()).toBe(true);
  // });

  it('should generate and verify a proof for an element', () => {
    const mmr = new MerkleMountainRange();
    const values = [Field(10), Field(20), Field(30), Field(40), Field(20), Field(30), Field(40), Field(20), Field(30), Field(40), Field(20), Field(30), Field(40)];
  
    values.forEach((value) => {
      mmr.append(value);
    });
  
    const leafIndex = UInt64.from(2); // Indices are 1-based
    const proof = mmr.getProof(leafIndex);
  
    // Verify the proof
    const isValid = mmr.verifyProof(values[1], proof); // values[1] corresponds to Field(20)
    expect(isValid.toBoolean()).toBe(true);
  });
  

  it('should fail verification for incorrect proof', () => {
    const mmr = new MerkleMountainRange();
    const values = [Field(100), Field(200), Field(300)];

    values.forEach((value) => {
      mmr.append(value);
    });

    const leafIndex = UInt64.from(2);
    const proof = mmr.getProof(leafIndex);

    // Tamper with the proof
    //proof.elementHash = Poseidon.hash([Field(999)]);
    proof.peaksHashes[0] = Poseidon.hash([Field(999)]);
    // Verify the proof
    const isValid = mmr.verifyProof(values[1], proof);
    expect(isValid.toBoolean()).toBe(false);
  });

  it('should clear the MMR', () => {
    const mmr = new MerkleMountainRange();
    mmr.append(Field(1));
    mmr.clear();

    expect(mmr.leavesCount).toEqual(UInt64.zero);
    expect(mmr.elementsCount).toEqual(UInt64.zero);
    expect(mmr.rootHash).toEqual(Field(0));
  });
});
