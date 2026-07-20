/**
 * Utilities for comparing facial biometric descriptors.
 * Descriptors are expected to be produced client-side (e.g. face-api.js / MediaPipe)
 * as fixed-length float embeddings and sent to the server for comparison only —
 * raw images never need to hit the backend.
 */

export function euclideanDistance(a: number[], b: number[]): number {
  if (a.length !== b.length) {
    throw new Error('Descriptor length mismatch.');
  }
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const diff = a[i] - b[i];
    sum += diff * diff;
  }
  return Math.sqrt(sum);
}

// Lower distance = more similar. 0.5-0.6 is a common working threshold for
// 128-d face-api.js embeddings — tune against your enrollment data / model.
export const FACE_MATCH_THRESHOLD = 0.5;