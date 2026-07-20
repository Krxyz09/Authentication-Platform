import * as faceapi from 'face-api.js';

// Models must be served as static files, e.g. placed in /public/models so they're
// reachable at https://yourapp/models/... Download the tiny_face_detector,
// face_landmark_68, and face_recognition weight files from the face-api.js repo:
// https://github.com/justadudewhohacks/face-api.js/tree/master/weights
const MODEL_URL = '/models';

let modelsLoadingPromise: Promise<void> | null = null;

export function loadFaceModels(): Promise<void> {
  if (!modelsLoadingPromise) {
    modelsLoadingPromise = Promise.all([
      faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
      faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
      faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL),
    ]).then(() => undefined);
  }
  return modelsLoadingPromise;
}

/**
 * Runs face detection + landmark + recognition against a live <video> element
 * and returns a 128-length descriptor array, or null if no face was found.
 * This descriptor is what gets sent to the backend for enrollment/comparison —
 * the raw video frame never leaves the browser.
 */
export async function captureFaceDescriptor(video: HTMLVideoElement): Promise<number[] | null> {
  const detection = await faceapi
    .detectSingleFace(video, new faceapi.TinyFaceDetectorOptions())
    .withFaceLandmarks()
    .withFaceDescriptor();

  if (!detection) return null;
  return Array.from(detection.descriptor);
}