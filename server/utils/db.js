// MongoDB connection and models for face authentication
import mongoose from 'mongoose';
const { Schema } = mongoose;

// Connect to MongoDB
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      dbName:'face-auth-db',
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
    return conn;
  } catch (error) {
    console.error(`Error connecting to MongoDB: ${error.message}`);
    process.exit(1);
  }
};

// User Schema
const userSchema = new Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  firstName: { type: String },
  lastName: { type: String },
  username: { type: String },
  email: { type: String, required: true },
  emailVerified: { type: Boolean, default: true },
  phoneNumber: { type: String },
  phoneNumberVerified: { type: Boolean, default: false },
  faceVerified: { type: Boolean, default: false },
  profilePicture: { type: String },  // Cloudinary URL
  registeredAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  faceProfileId: { type: String },
});

// Face Profile Schema
const faceProfileSchema = new Schema({
  userId: { type: String, required: true, unique: true },
  faceImagePath: { type: String, required: true },
  faceDescriptor: { type: Array }, // Store face-api.js descriptor as array
  registeredAt: { type: Date, default: Date.now },
});

// OAuth Token Schema
const tokenSchema = new Schema({
  token: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  clientId: { type: String, required: true },
  scope: { type: String },
  isRefreshToken: { type: Boolean, default: false },
  expiresAt: { type: Date, required: true },
});

// Authorization Code Schema
const authCodeSchema = new Schema({
  code: { type: String, required: true, unique: true },
  clientId: { type: String, required: true },
  userId: { type: String, required: true },
  redirectUri: { type: String, required: true },
  scope: { type: String },
  expiresAt: { type: Date, required: true },
  nonce: { type: String },
});

// Create models
const User = mongoose.models.User || mongoose.model('User', userSchema);
const FaceProfile = mongoose.models.FaceProfile || mongoose.model('FaceProfile', faceProfileSchema);
const Token = mongoose.models.Token || mongoose.model('Token', tokenSchema);
const AuthCode = mongoose.models.AuthCode || mongoose.model('AuthCode', authCodeSchema);

export { connectDB, User, FaceProfile, Token, AuthCode };