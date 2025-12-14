// netlify/functions/api.js
const serverless = require('serverless-http');
// CHANGE 1: Import populateInitialData and mongoose from server.js
const { app, populateInitialData, mongoose } = require('../../server'); // Path to your Express app (server.js)

// Cache the database connection across warm invocations
let cachedDb = null;

async function connectToDatabase() {
    if (cachedDb && mongoose.connection.readyState === 1) {
        console.log('MongoDB already connected. Reusing connection.');
        return cachedDb;
    }

    console.log('Connecting to MongoDB...');
    try {
        cachedDb = await mongoose.connect(process.env.MONGODB_URI, { // Use MONGO_URI, not MONGODB_URI if that's your env var name
            bufferCommands: false,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        console.log('MongoDB connected successfully!');

        // CHANGE 2: Call populateInitialData after successful connection
        console.log('Attempting to populate initial data...');
        await populateInitialData(); // This will create the admin user if not present
        console.log('Initial data population attempt complete.');

        return cachedDb;
    } catch (error) {
        console.error('MongoDB connection error:', error);
        cachedDb = null; // Clear cache on failure to force re-connection next time
        throw error; // Re-throw to propagate the error up
    }
}

// Wrap your Express app with serverless-http
const handler = serverless(app);

// Netlify Function handler
exports.handler = async (event, context) => {
    // Ensure the database connection is established BEFORE processing the request
    try {
        await connectToDatabase();
    } catch (dbError) {
        console.error('Handler caught DB connection error:', dbError);
        return {
            statusCode: 500,
            body: JSON.stringify({ message: 'Database connection failed.', error: dbError.message }),
        };
    }

    // Now, let serverless-http handle the request and pass it to Express.
    console.log('[Netlify Function] Passing raw event to serverless-http for Express processing...');
    return handler(event, context);
};