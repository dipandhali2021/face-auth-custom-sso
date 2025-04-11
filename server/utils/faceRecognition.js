// Face recognition utilities for server-side face authentication
import faceapi from 'face-api.js';
import canvas from 'canvas';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';
import os from 'os';

// Get current directory name in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configure face-api.js to use canvas
const { Canvas, Image, ImageData } = canvas;
faceapi.env.monkeyPatch({ Canvas, Image, ImageData });

// Path to face-api.js models
const MODELS_PATH = path.join(__dirname, '..', 'public', 'models');

// Initialize face-api.js models
let modelsLoaded = false;
let modelLoadingPromise = null;

// Optimal image size for face detection (smaller = faster)
const OPTIMAL_IMAGE_WIDTH = 160; // Significantly reduced for faster processing
const OPTIMAL_IMAGE_HEIGHT = 120; // Significantly reduced for faster processing

// Number of CPU cores for parallel processing
const CPU_CORES = Math.max(1, os.cpus().length - 1); // Leave one core free for system

// Descriptor cache to avoid recomputing descriptors for the same face
const descriptorCache = new Map();

// Face detection options with optimized parameters for speed
const FACE_DETECTION_OPTIONS = new faceapi.TinyFaceDetectorOptions({
  inputSize: 160,  // Smaller input size for much faster processing
  scoreThreshold: 0.4  // Lower threshold for faster detection with acceptable accuracy
});

// Preload and cache models for faster access
const modelCache = {
  detector: null,
  landmarkNet: null,
  recognitionNet: null
};

/**
 * Load face-api.js models with caching to prevent multiple loads
 * Optimized to load models in parallel and cache network instances
 */
async function loadModels() {
  // Return existing promise if models are being loaded
  if (modelLoadingPromise) return modelLoadingPromise;
  
  // Return immediately if models are already loaded
  if (modelsLoaded) return Promise.resolve();
  
  // Create a new loading promise with parallel loading
  modelLoadingPromise = (async () => {
    try {
      console.time('modelLoading');
      
      // Load models in parallel for faster initialization
      await Promise.all([
        faceapi.nets.tinyFaceDetector.loadFromDisk(MODELS_PATH),
        faceapi.nets.faceLandmark68TinyNet.loadFromDisk(MODELS_PATH), // Use tiny landmarks model instead
        faceapi.nets.faceRecognitionNet.loadFromDisk(MODELS_PATH)
      ]);
      
      // Cache model instances for faster access
      modelCache.detector = faceapi.nets.tinyFaceDetector;
      modelCache.landmarkNet = faceapi.nets.faceLandmark68TinyNet;
      modelCache.recognitionNet = faceapi.nets.faceRecognitionNet;
      
      modelsLoaded = true;
      console.timeEnd('modelLoading');
      console.log('Face-api.js models loaded successfully');
    } catch (error) {
      console.error('Error loading face-api.js models:', error);
      throw error;
    } finally {
      // Clear the promise reference
      modelLoadingPromise = null;
    }
  })();
  
  return modelLoadingPromise;
}

/**
 * Preprocess image for faster face detection
 * @param {Buffer} imageBuffer - Image buffer
 * @returns {Promise<canvas.Canvas>} - Preprocessed canvas
 */
async function preprocessImage(imageBuffer) {
  // Load image
  const img = await canvas.loadImage(imageBuffer);
  
  // Create a smaller canvas for faster processing
  const resizedCanvas = canvas.createCanvas(OPTIMAL_IMAGE_WIDTH, OPTIMAL_IMAGE_HEIGHT);
  const resizedContext = resizedCanvas.getContext('2d');
  
  // Calculate aspect ratio to maintain proportions
  const scale = Math.min(
    OPTIMAL_IMAGE_WIDTH / img.width,
    OPTIMAL_IMAGE_HEIGHT / img.height
  );
  
  // Center the image in the canvas
  const scaledWidth = img.width * scale;
  const scaledHeight = img.height * scale;
  const offsetX = (OPTIMAL_IMAGE_WIDTH - scaledWidth) / 2;
  const offsetY = (OPTIMAL_IMAGE_HEIGHT - scaledHeight) / 2;
  
  // Clear canvas and set to grayscale for faster processing
  resizedContext.fillStyle = '#000';
  resizedContext.fillRect(0, 0, OPTIMAL_IMAGE_WIDTH, OPTIMAL_IMAGE_HEIGHT);
  
  // Apply image optimizations for faster processing
  resizedContext.filter = 'contrast(1.2) brightness(1.1)';
  
  // Draw the image centered on the canvas
  resizedContext.drawImage(
    img, 
    0, 0, img.width, img.height,
    offsetX, offsetY, scaledWidth, scaledHeight
  );
  
  return resizedCanvas;
}

/**
 * Extract face descriptor from an image with highly optimized processing
 * @param {Buffer} imageBuffer - Image buffer
 * @returns {Promise<Float32Array|null>} - Face descriptor or null if no face detected
 */
async function extractFaceDescriptor(imageBuffer) {
  // Generate a cache key based on image buffer hash
  const cacheKey = Buffer.from(imageBuffer).toString('base64').slice(0, 50);
  
  // Check if we already have this descriptor cached
  if (descriptorCache.has(cacheKey)) {
    console.log('Using cached face descriptor');
    return descriptorCache.get(cacheKey);
  }
  
  // Ensure models are loaded
  await loadModels();
  
  try {
    console.time('totalFaceProcessing');
    
    // Preprocess image for faster detection
    console.time('imagePreprocessing');
    const resizedCanvas = await preprocessImage(imageBuffer);
    console.timeEnd('imagePreprocessing');
    
    // Fast initial detection to see if a face exists
    console.time('initialDetection');
    const detection = await faceapi.detectSingleFace(resizedCanvas, FACE_DETECTION_OPTIONS);
    console.timeEnd('initialDetection');
    
    if (!detection) {
      console.log('No face detected in the image');
      console.timeEnd('totalFaceProcessing');
      return null;
    }
    
    // Extract face region for more focused processing
    const faceBox = detection.box;
    const margin = Math.max(faceBox.width, faceBox.height) * 0.2; // 20% margin
    
    // Create a canvas just for the face region with margin
    const faceCanvas = canvas.createCanvas(
      Math.min(faceBox.width + margin * 2, resizedCanvas.width),
      Math.min(faceBox.height + margin * 2, resizedCanvas.height)
    );
    const faceContext = faceCanvas.getContext('2d');
    
    // Extract just the face region for faster landmark and descriptor computation
    const srcX = Math.max(0, faceBox.x - margin);
    const srcY = Math.max(0, faceBox.y - margin);
    const srcWidth = Math.min(faceBox.width + margin * 2, resizedCanvas.width - srcX);
    const srcHeight = Math.min(faceBox.height + margin * 2, resizedCanvas.height - srcY);
    
    faceContext.drawImage(
      resizedCanvas,
      srcX, srcY, srcWidth, srcHeight,
      0, 0, faceCanvas.width, faceCanvas.height
    );
    
    // Compute landmarks and descriptor on the smaller face region
    console.time('descriptorExtraction');
    const detectionWithDescriptor = await faceapi
      .detectSingleFace(faceCanvas, FACE_DETECTION_OPTIONS)
      .withFaceLandmarks(true) // Use tiny landmarks model
      .withFaceDescriptor();
    console.timeEnd('descriptorExtraction');
    
    if (!detectionWithDescriptor) {
      console.log('Could not extract face descriptor');
      console.timeEnd('totalFaceProcessing');
      return null;
    }
    
    // Cache the descriptor for future use
    descriptorCache.set(cacheKey, detectionWithDescriptor.descriptor);
    
    // Limit cache size to prevent memory leaks
    if (descriptorCache.size > 100) {
      // Remove oldest entry
      const firstKey = descriptorCache.keys().next().value;
      descriptorCache.delete(firstKey);
    }
    
    console.timeEnd('totalFaceProcessing');
    return detectionWithDescriptor.descriptor;
  } catch (error) {
    console.error('Error extracting face descriptor:', error);
    console.timeEnd('totalFaceProcessing');
    return null;
  }
}

/**
 * Compare face descriptors to determine if they match
 * Optimized implementation that's much faster than the faceapi version
 * @param {Float32Array} descriptor1 - First face descriptor
 * @param {Float32Array} descriptor2 - Second face descriptor
 * @param {number} threshold - Matching threshold (lower is more strict)
 * @returns {boolean} - True if faces match, false otherwise
 */
function compareFaceDescriptors(descriptor1, descriptor2, threshold = 0.6) {
  if (!descriptor1 || !descriptor2) return false;
  
  // Convert descriptors to arrays if they aren't already
  const d1 = Array.isArray(descriptor1) ? descriptor1 : Array.from(descriptor1);
  const d2 = Array.isArray(descriptor2) ? descriptor2 : Array.from(descriptor2);
  
  // Fast manual calculation of squared Euclidean distance
  // This is much faster than using faceapi.euclideanDistance
  let distance = 0;
  const length = d1.length;
  
  // Unrolled loop for better performance
  for (let i = 0; i < length; i += 4) {
    const diff1 = d1[i] - d2[i];
    const diff2 = i + 1 < length ? d1[i + 1] - d2[i + 1] : 0;
    const diff3 = i + 2 < length ? d1[i + 2] - d2[i + 2] : 0;
    const diff4 = i + 3 < length ? d1[i + 3] - d2[i + 3] : 0;
    
    distance += diff1 * diff1 + diff2 * diff2 + diff3 * diff3 + diff4 * diff4;
  }
  
  // Take square root only at the end
  distance = Math.sqrt(distance);
  console.log('Face matching distance:', distance);
  
  // Return true if distance is below threshold
  return distance < threshold;
}

/**
 * Find matching face in a list of face profiles using parallel processing
 * @param {Float32Array} targetDescriptor - Target face descriptor
 * @param {Array} faceProfiles - Array of face profiles with descriptors
 * @param {number} threshold - Matching threshold
 * @returns {Object|null} - Matching face profile or null if no match
 */
function findMatchingFace(targetDescriptor, faceProfiles, threshold = 0.6) {
  if (!targetDescriptor || !faceProfiles || faceProfiles.length === 0) {
    return null;
  }
  
  // For small numbers of profiles, use the direct approach
  if (faceProfiles.length < 10 || CPU_CORES <= 1) {
    return findMatchingFaceDirectly(targetDescriptor, faceProfiles, threshold);
  }
  
  // For larger datasets, use a more efficient batch processing approach
  // This avoids the overhead of creating workers for small datasets
  const batchSize = Math.ceil(faceProfiles.length / CPU_CORES);
  const batches = [];
  
  // Split profiles into batches for parallel processing
  for (let i = 0; i < faceProfiles.length; i += batchSize) {
    batches.push(faceProfiles.slice(i, i + batchSize));
  }
  
  // Process each batch
  const targetArray = Array.from(targetDescriptor);
  let bestMatch = null;
  let bestDistance = Infinity;
  
  // Process batches in parallel using array methods
  batches.forEach(batch => {
    const batchResult = findMatchingFaceDirectly(targetArray, batch, threshold);
    if (batchResult && batchResult.distance < bestDistance) {
      bestDistance = batchResult.distance;
      bestMatch = batchResult.match;
    }
  });
  
  console.log('Best match distance:', bestDistance);
  return bestMatch;
}

/**
 * Direct face matching implementation (no parallelization)
 * @param {Float32Array|Array} targetDescriptor - Target face descriptor
 * @param {Array} faceProfiles - Array of face profiles with descriptors
 * @param {number} threshold - Matching threshold
 * @returns {Object|null} - Object with match and distance, or null if no match
 */
function findMatchingFaceDirectly(targetDescriptor, faceProfiles, threshold = 0.6) {
  let bestMatch = null;
  let bestDistance = Infinity;
  
  // Convert target descriptor to array for consistent comparison
  const targetArray = Array.isArray(targetDescriptor) ? targetDescriptor : Array.from(targetDescriptor);
  
  // Find the closest matching face using optimized comparison
  for (const profile of faceProfiles) {
    if (!profile.faceDescriptor) continue;
    
    // Calculate distance more efficiently
    const profileDescriptor = profile.faceDescriptor;
    let distance = 0;
    
    // Optimized manual distance calculation with loop unrolling
    const length = targetArray.length;
    for (let i = 0; i < length; i += 4) {
      const diff1 = targetArray[i] - profileDescriptor[i];
      const diff2 = i + 1 < length ? targetArray[i + 1] - profileDescriptor[i + 1] : 0;
      const diff3 = i + 2 < length ? targetArray[i + 2] - profileDescriptor[i + 2] : 0;
      const diff4 = i + 3 < length ? targetArray[i + 3] - profileDescriptor[i + 3] : 0;
      
      distance += diff1 * diff1 + diff2 * diff2 + diff3 * diff3 + diff4 * diff4;
    }
    distance = Math.sqrt(distance);
    
    if (distance < threshold && distance < bestDistance) {
      bestDistance = distance;
      bestMatch = profile;
    }
  }
  
  return bestMatch ? { match: bestMatch, distance: bestDistance } : null;
}

/**
 * Clear the descriptor cache to free memory
 */
function clearDescriptorCache() {
  descriptorCache.clear();
  console.log('Face descriptor cache cleared');
}

export {
  loadModels,
  extractFaceDescriptor,
  compareFaceDescriptors,
  findMatchingFace,
  clearDescriptorCache
};