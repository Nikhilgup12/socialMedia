
const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const app = express();
const QRCode = require('qrcode');
app.use(express.json());
app.use(cors());

// Serve static files from the 'uploads' directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configure multer for disk storage
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/'); // Folder to save uploaded files
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });

let client;
const initializeDBAndServer = async () => {
    const username = encodeURIComponent("Nikhil");
    const password = encodeURIComponent("Nikhil#123");

    const uri = `mongodb+srv://${username}:${password}@cluster0.lmgtktf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

    client = new MongoClient(uri);

    try {
        await client.connect();
        console.log("Connected to MongoDB.....");
        app.listen(3000, () => {
            console.log('Server running on port: 3000');
        });
    } catch (error) {
        console.error("Error connecting to MongoDB:", error);
        process.exit(1);
    }
};

initializeDBAndServer();


// Middleware to authenticate JWT token
const authenticateToken = (request, response, next) => {
    let jwtToken;
    const authHeader = request.headers["authorization"];
    if (authHeader !== undefined) {
        jwtToken = authHeader.split(" ")[1];
    }
    if (jwtToken === undefined) {
        response.status(401);
        response.send("Invalid JWT Token");
    } else {
        jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
            if (error) {
                response.status(401);
                response.send({ "Invalid JWT Token": error });
            } else {
                request.userId = payload.userId;
                next();
            }
        });
    }
};



// Endpoint to register a new user
app.post('/register', upload.single('profilePhoto'), async (req, res) => {
    try {
        const collection = client.db('socialmedia').collection('User');
        const { name, phone, email, password } = req.body;

        // Check if the email already exists
        const existingUser = await collection.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ errorMsg: 'User with this Email ID already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate the URL for the uploaded file
        let profilePhotoUrl = null;
        if (req.file) {
            const fileName = req.file.filename;
            profilePhotoUrl = `${req.protocol}://${req.get('host')}/uploads/${fileName}`; // Construct the URL
        }

        // Create a new user document
        const newUser = {
            name,
            phone,
            profilePhoto: profilePhotoUrl, // Store the file URL in MongoDB
            email,
            password: hashedPassword // Store the hashed password
        };

        // Save the new user to the database
        const result = await collection.insertOne(newUser);
        const userId = result.insertedId;

        // Generate QR Code URL
        const qrCodeUrl = `${req.protocol}://${req.get('host')}/profile/${userId}`;
        const qrCodeFilePath = path.join(__dirname, 'uploads', `qrCode-${userId}.png`);
        await QRCode.toFile(qrCodeFilePath, qrCodeUrl);

        const qrCodeImageUrl = `${req.protocol}://${req.get('host')}/uploads/qrCode-${userId}.png`;

        await collection.updateOne({ _id: userId }, { $set: { qrCode: qrCodeImageUrl } });
        res.status(200).json({ yourId: userId, qrCode: qrCodeImageUrl, message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ "Internal server error:": error.message });
    }
});



app.post('/login', async (request, response) => {
    try {
        // Use your specific database and collection names
        const collection = client.db('socialmedia').collection('User'); 
        const userDetails = request.body;
        const { email, password } = userDetails;

        // Check if the user exists
        const isUserExist = await collection.findOne({ email });
        if (!isUserExist) {
            response.status(401);
            response.send({ errorMsg: "User with this Email ID doesn't exist" });
            return;
        }

        // Compare the provided password with the stored hashed password
        const isPasswordMatched = await bcrypt.compare(password, isUserExist.password);
        if (isPasswordMatched) {
            // Generate a JWT token with the user's ID
            const token = jwt.sign({ userId: isUserExist._id }, "MY_SECRET_TOKEN");
            response.status(200);
            response.send({ jwtToken: token, userId: isUserExist._id });
        } else {
            response.status(401);
            response.send({ errorMsg: "Incorrect password" });
        }
    } catch (error) {
        response.status(500);
        response.send({ "Internal server error:": error });
    }
});


app.get('/user-details', authenticateToken, async (req, res) => {
    try {
        const collection = client.db('socialmedia').collection('User');
        const user = await collection.findOne({ _id: new ObjectId(req.userId) });
    
        if (!user) {
            return res.status(404).json({ errorMsg: "User not found" });
        }

        // Ensure QR code is included in the response
        const { password, ...userDetails } = user;
        res.status(200).json(userDetails);
    } catch (error) {
        res.status(500).json({ "Internal server error:": error.message });
    }
});

app.get('/profile/:userId', async (req, res) => {
    try {
        const collection = client.db('socialmedia').collection('User');
        const userId = req.params.userId;
        const user = await collection.findOne({ _id: new ObjectId(userId) });

        if (!user) {
            return res.status(404).json({ errorMsg: "User not found" });
        }

        const { password, ...userDetails } = user;
        res.status(200).json(userDetails);
    } catch (error) {
        res.status(500).json({ "Internal server error:": error.message });
    }
});



