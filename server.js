require("dotenv").config();
const express = require("express");
const axios = require("axios");
const cors = require("cors");
const PORT = 5000;
const app = express();

app.use(cors());
app.use(express.static("public")); // Serve frontend files
app.set("view engine", "ejs");

// Fetch Live Gas Fees
app.get("/gas-fees", async (req, res) => {
    try {
        const ethGas = await axios.get(`https://api.etherscan.io/api?module=gastracker&action=gasoracle&apikey=${process.env.ETHERSCAN_API_KEY}`);
        const polygonGas = await axios.get("https://gasstation.polygon.technology/v2");
        const bscGas = await axios.get(`https://api.bscscan.com/api?module=gastracker&action=gasoracle&apikey=${process.env.BSCSCAN_API_KEY}`);

        res.json({
            ethereum: ethGas.data.result,
            polygon: polygonGas.data,
            binance_smart_chain: bscGas.data.result,
        });
    } catch (error) {
        res.status(500).json({ error: "Error fetching gas fees", details: error.message });
    }
});

// Fetch Live Exchange Rates
app.get("/usdt-rate", async (req, res) => {
    const { currency } = req.query;

    if (!currency) {
        return res.status(400).json({ error: "Currency is required" });
    }

    try {
        const response = await axios.get(
            `https://api.coinbase.com/v2/exchange-rates?currency=USDT`
        );

        console.log("API Response:", response.data); // Debugging

        const rate = response.data.data.rates[currency.toUpperCase()];

        if (!rate) {
            return res.status(404).json({ error: "Invalid currency or rate not available" });
        }

        res.json({ rate: parseFloat(rate).toFixed(2) });

    } catch (error) {
        console.error("Error fetching USDT rate:", error);
        res.status(500).json({ error: "Failed to fetch USDT rate" });
    }
});

// Render Frontend
app.get("/", (req, res) => {
    res.render("home");
});
if(process.env.NODE_ENV != "production"){
    require("dotenv").config();
  };
  const mongoose = require('mongoose');
  const path = require('path');
  const bodyParser = require('body-parser');
  const passport = require('passport');
  const LocalStrategy = require('passport-local').Strategy;
  const session = require('express-session');
  const MongoStore = require('connect-mongo');
  const flash = require('connect-flash');
  const nodemailer = require('nodemailer');
  const User = require('./models/user'); // User model
  const Site = require('./models/site');
  const scrapeLinkedInJobs = require('./models/scrapeLinkedIn');
  const ConnectWithUs = require('./models/ConnectWithUs');
  const fetchUnstopJobs = require('./models/unstop');
  const fetchGoogleJobs = require('./models/googleapis');
  const Web3 = require('web3');
  const multer = require('multer');
  const { cloudinary, storage } = require('./cloudConfig'); 
  const upload = multer({ storage: storage }); // 'image' is the field name
  const stripe = require('stripe')('sk_test_51QaE8BKgI6RI6Rg5BhI6PIJG6857h8pxtWZEdxaxdMiWVnIww3sfolPot5hrld484cjifCSBUNrb6P7478q74Xu400dcp6Sz15');
  const dbUrl = process.env.ATLASDB_URL;
  const contractAddress = '0x60db8d0a13f0e43a724357b0168022deefaf9836'; // Replace with your contract address
  const contractABI = [
      {
          "inputs": [],
          "name": "fundContract",
          "outputs": [],
          "stateMutability": "payable",
          "type": "function"
      },
      {
          "inputs": [],
          "name": "markWorkCompleted",
          "outputs": [],
          "stateMutability": "nonpayable",
          "type": "function"
      },
      {
          "inputs": [],
          "name": "releasePayment",
          "outputs": [],
          "stateMutability": "nonpayable",
          "type": "function"
      },
      {
          "inputs": [
              {
                  "internalType": "address",
                  "name": "_freelancer",
                  "type": "address"
              },
              {
                  "internalType": "uint256",
                  "name": "_paymentAmount",
                  "type": "uint256"
              }
          ],
          "stateMutability": "nonpayable",
          "type": "constructor"
      },
      {
          "inputs": [],
          "name": "contractBalance",
          "outputs": [
              {
                  "internalType": "uint256",
                  "name": "",
                  "type": "uint256"
              }
          ],
          "stateMutability": "view",
          "type": "function"
      },
      {
          "inputs": [],
          "name": "employer",
          "outputs": [
              {
                  "internalType": "address",
                  "name": "",
                  "type": "address"
              }
          ],
          "stateMutability": "view",
          "type": "function"
      },
      {
          "inputs": [],
          "name": "freelancer",
          "outputs": [
              {
                  "internalType": "address",
                  "name": "",
                  "type": "address"
              }
          ],
          "stateMutability": "view",
          "type": "function"
      },
      {
          "inputs": [],
          "name": "paymentAmount",
          "outputs": [
              {
                  "internalType": "uint256",
                  "name": "",
                  "type": "uint256"
              }
          ],
          "stateMutability": "view",
          "type": "function"
      },
      {
          "inputs": [],
          "name": "workCompleted",
          "outputs": [
              {
                  "internalType": "bool",
                  "name": "",
                  "type": "bool"
              }
          ],
          "stateMutability": "view",
          "type": "function"
      }
  ];
  const { connect } = require("http2");
  
  
  // Initialize the Express app
  mongoose.connect(process.env.ATLASDB_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    tls: true, // Enable TLS explicitly
    tlsAllowInvalidCertificates: false, // Ensures valid SSL certificates
    serverSelectionTimeoutMS: 5000,
  })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log('MongoDB connection error:', err));
  
  const store = MongoStore.create({
      mongoUrl: dbUrl,
      crypto: {
          secret: process.env.SECRET,
      },
      touchAfter: 24 * 3600,
  });
  
  store.on("error", (err) => {
    console.log("ERROR IN MONGO SESSION", err);
  });
  
  
  const sessionOptions = {
      store,
      secret: process.env.SECRET,
      resave: false,
      saveUninitialized: true,
      cookie:{
          expires: Date.now() + 7 * 24  * 60 * 60 * 1000,
          maxAge:  7 * 24  * 60 * 60 * 1000,
          httpOnly: true 
      },
  };
  
  // Session setup with MongoStore for persistent sessions
  app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key', // Use environment variable for production
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' } // Ensure cookies are secure in production (HTTPS)
  }));
  
  app.use(cors());
  app.use(express.json());
  
  // Passport.js configuration
  passport.use(new LocalStrategy(
    async (username, password, done) => {
      try {
        const user = await User.findOne({ username });
        if (!user) return done(null, false, { message: 'Incorrect username.' });
  
        const isMatch = await user.comparePassword(password);
        if (!isMatch) return done(null, false, { message: 'Incorrect password.' });
  
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  ));
  
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  
  passport.deserializeUser(async (id, done) => {
    const user = await User.findById(id);
    done(null, user);
  });
  
  // Middleware
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(express.static(path.join(__dirname, 'public')));
  app.set('view engine', 'ejs');
  
  // Initialize Passport.js
  app.use(passport.initialize());
  app.use(passport.session());
  
  // Initialize connect-flash for storing flash messages
  app.use(flash());
  
  // Middleware to expose flash messages and user to views
  app.use((req, res, next) => {
    res.locals.error = req.flash('error');
    res.locals.success = req.flash('success');
    res.locals.user = req.user || null; // Make user available in views
    next();
  });
  
  let currentAccount = null;
  
  app.post('/connect-metamask', (req, res) => {
    const { account } = req.body;
  
    // Validate account field
    if (!account) {
        return res.status(400).json({ message: 'Account is required to connect MetaMask' });
    }
  
    // Store the account address
    accounts.push(account);
  
    // Respond with success message
    res.status(200).json({ message: 'MetaMask connected successfully.', account });
  });
  
  
  // Route to create contract
  app.post('/create-contract', async (req, res) => {
    const { employerAddress, freelancerAddress, paymentAmount } = req.body;
  
    if (!employerAddress || !freelancerAddress || !paymentAmount || !currentAccount) {
      return res.status(400).json({ error: 'Missing required parameters' });
    }
  
    // Placeholder response - no actual contract creation in backend (done in frontend with MetaMask)
    res.status(200).json({ message: 'Contract created successfully' });
  });
  
  app.post('/upload', upload.single('siteImage'), async (req, res) => {
    if (!req.file) {
      return res.status(400).send('No file uploaded');
    }
  
    try {
      // Log the response from Cloudinary directly
      console.log('Uploaded File Info:', req.file);
  
      if (req.file && req.file.path) {
        // If Cloudinary response is successful
        console.log('Cloudinary Upload Success:', req.file);
  
        // Now save the data to your database
        const siteData = {
          siteName: req.body.siteName,
          siteUrl: req.body.siteUrl,
          description: req.body.description,
          price: req.body.price,
          githubUrl: req.body.githubUrl,
          image: {
            url: req.file.path,     // Cloudinary URL
            filename: req.file.filename, // Cloudinary public ID
          },
        };
  
        Site.create(siteData, (err, site) => {
          if (err) {
            console.log('Error saving site:', err);
            return res.status(500).send('Error saving site');
          }
  
          res.redirect('/all-websites');
        });
      } else {
        console.log('Error: Cloudinary did not return the expected response.');
        return res.status(500).send('Error uploading image');
      }
    } catch (err) {
      console.log('Error uploading to Cloudinary:', err);
      res.status(500).send('Error uploading image');
    }
  });
  
  app.post('/contact-us', upload.single('image'), async (req, res) => {
    // Check if the form is submitted with data
    if (!req.body.name || !req.body.email || !req.body.message) {
      return res.status(400).send('All fields are required');
    }
  
    try {
      // Log form data
      console.log('Form Data:', req.body);
      console.log('Uploaded Image:', req.file);
  
      let imageUrl = null;
      let imageFilename = null;
  
      // If an image is uploaded, upload to Cloudinary
      if (req.file) {
        const result = await cloudinary.uploader.upload(req.file.buffer, {
          folder: 'contact_us_images'  // Optional: store images in a specific folder
        });
        imageUrl = result.secure_url;
        imageFilename = result.public_id;
        console.log('Image uploaded to Cloudinary:', result);
      }
  
      // Save the contact message in your database
      const contactMessage = {
        name: req.body.name,
        email: req.body.email,
        message: req.body.message,
        image: {
          url: imageUrl,
          filename: imageFilename
        }
      };
  
      // Save to the database (example: using Mongoose)
      try {
        const savedMessage = await Contact.create(contactMessage);
        console.log('Message saved:', savedMessage);
        res.send('Your message has been submitted successfully!');
      } catch (err) {
        console.log('Error saving message:', err);
        res.status(500).send('Error saving message');
      }
    } catch (err) {
      console.log('Error processing form:', err);
      res.status(500).send('Error processing the form');
    }
  });
  
  // Routes
  
  // Home route
  app.get('/', (req, res) => {
    // Pass 'orderSuccess' query to the homepage view
    res.render('index', { orderSuccess: req.query.orderSuccess || false });
  });
  
  app.get('/contract', (req, res) => {
    // Pass 'orderSuccess' query to the homepage view
    res.render('contract');
  });
  
  
  // Login form
  app.get('/login', (req, res) => {
    res.render('login', { title: 'Login' });
  });
  
  // Handle login (post)
  app.post('/login', passport.authenticate('local', {
    successRedirect: '/earn',
    failureRedirect: '/login',
    failureFlash: true
  }));
  
  // Route to display all published websites from all users
  app.get('/all-websites',isAuthenticated, async (req, res) => {
    try {
        // Fetch all sites from the database
        const allSites = await Site.find();  // Get all the published sites
  
        // Check if there are any sites
        if (allSites.length === 0) {
            // If no sites are found, pass an empty array or a custom message to the view
            res.render('all-websites', { sites: [], title: 'All Published Websites' });
        } else {
            // If sites are found, pass them to the view
            res.render('all-websites', { sites: allSites, title: 'All Published Websites' });
        }
    } catch (err) {
        console.error('Error fetching sites:', err);
        res.status(500).send('Error fetching sites');
    }
  });
  
  // Route to handle form submission (POST request for /connect)
  // POST route for handling form submission
  app.get('/connect', async (req, res) => {
    try {
        // Fetch the most recently added user
        const connect = await ConnectWithUs.findOne().sort({ _id: -1 });
  
        // If no users exist in the database
        if (!connect) {
            return res.status(404).send("No user data found!");
        }
  
        // Render the page with user data
        res.render('connect', { connect });
  
    } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).send("Internal Server Error");
    }
  });
  
  // Route to handle form submission
  app.post("/connect", upload.single("imageUrl"), async (req, res) => {
    try {
      const { name, github, linkedin, metamask, skills } = req.body;
  
      if (!req.file) {
        return res.status(400).json({ error: "Image is required!" });
      }
  
      const newUser = new ConnectWithUs({
        name,
        github,
        linkedin,
        metamask,
        skills,
        image: {
          url: req.file.path,  // Cloudinary URL
          filename: req.file.filename,
        },
      });
  
      await newUser.save();
      res.json({ message: "User connected successfully!", user: newUser });
  
    } catch (error) {
      console.error("Error connecting user:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  });
  // GET route for displaying all profiles or a single profile
  app.get('/contact-us', async (req, res) => {
    try {
      const connectWithUs = await ConnectWithUs.find();  // Fetch data from the model
  
      // Pass the data to the view (ensure the variable names match)
      res.render('connect', { connectWithUs, title: 'Member Profile',connect});
    } catch (err) {
      console.log('Error fetching ConnectWithUs data:', err);
      res.status(500).send('Error fetching data');
    }
  });
  
  
  // Register form
  app.get('/register', (req, res) => {
    res.render('register', { title: 'Register' });
  });

  app.get("/live",(req,res)=>{
    res.render("index");
  });
  
  // Example of updating the 'published' status of a site
  app.post('/publish-site/:siteId', isAuthenticated, async (req, res) => {
    const { siteId } = req.params;
  
    try {
      const site = await Site.findById(siteId);
      if (!site) {
        req.flash('error', 'Site not found');
        return res.redirect('/earn');
      }
  
      // Set the 'published' field to true
      site.published = true;
      await site.save();
  
      req.flash('success', 'Site published successfully!');
      res.redirect('/earn');
    } catch (err) {
      console.log(err);
      req.flash('error', 'Error publishing site');
      res.redirect('/earn');
    }
  });
  
  
  // Handle registration (post)
  app.post('/register', async (req, res) => {
    const { username, password } = req.body;
  
    try {
      // Ensure that username and password are provided
      if (!username || !password) {
        req.flash('error', 'Username and password are required');
        return res.redirect('/register');
      }
  
      // Check if the user already exists by username
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        req.flash('error', 'Username already exists. Please choose another one.');
        return res.redirect('/register');
      }
  
      // Create a new user without email
      const newUser = new User({ username, password });
      await newUser.save();
  
      req.flash('success', 'Registration successful! Please log in.');
      return res.redirect('/login');
    } catch (err) {
      console.error('Error registering user:', err);
      req.flash('error', 'Error registering user. Please try again.');
      return res.redirect('/register');
    }
  });
  
  
  
  
  // Shop page (requires login)
  app.get('/shop', isAuthenticated, (req, res) => {
    res.render('shop', { title: 'Shop' });
  });
  
  // Order submission route (for sending email)
  app.post('/submit-order', isAuthenticated, async (req, res) => {
    const { fullName, email, phone, websiteRequirement, techStack, collegeName } = req.body;
  
    const Order = require('./models/order');
    const order = new Order({
      fullName,
      email,
      phone,
      websiteRequirement,
      techStack,
      collegeName,
    });
  
    try {
      // Save the order to the database (Optional)
      await order.save();
  
      // Configure the email content
      const mailOptions = {
        from: 'your-email@gmail.com',
        to: 'raghavrock098@gmail.com',  // Destination email address
        subject: 'New Website Order Submission',
        html: `
          <h3>New Website Order</h3>
          <p><strong>Full Name:</strong> ${fullName}</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Phone Number:</strong> ${phone}</p>
          <p><strong>Website Requirements:</strong> ${websiteRequirement}</p>
          <p><strong>Technology Stack:</strong> ${techStack}</p>
          <p><strong>College Name:</strong> ${collegeName}</p>
        `,
      };
  
      // Send the email
      transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
          console.log('Error sending email:', err);
          req.flash('error', 'Error submitting the order. Please try again later.');
          return res.redirect('/shop');
        } else {
          console.log('Email sent: ' + info.response);
          req.flash('success', 'Your order has been submitted successfully!');
          return res.redirect('/shop');
        }
      });
    } catch (err) {
      console.log('Error saving order:', err);
      req.flash('error', 'Error submitting the order. Please try again later.');
      res.redirect('/shop');
    }
  });
  
  // Earn page (requires login)
  // Route to display the 'earn' page
  // Updated /earn route to send `showPublishForm`
  app.get('/earn', isAuthenticated, async (req, res) => {
    try {
      const userId = req.user._id; // Access the logged-in user's ID
      const sites = await Site.find({ user: userId }); // Fetch user's published sites
  
      // Calculate total earnings (optional)
      const totalEarnings = sites.reduce((acc, site) => acc + site.earnings, 0);
  
      // Render the 'earn' page with the user's sites and total earnings
      res.render('earn', { 
        title: 'Earn', 
        user: req.user, 
        sites, 
        totalEarnings, 
        showPublishForm: false 
      });
    } catch (error) {
      console.error("Error fetching sites:", error);
      res.status(500).send("Server Error");
    }
  });
  
  app.get('/earn/edit/:id', async (req, res) => {
    try {
        const site = await Site.findById(req.params.id);
        res.render('editSite', { site });  // Render the updated site data to the form
    } catch (error) {
        console.error(error);
        res.status(500).send('Error fetching site details');
    }
  });
  
  
  
  app.post('/earn/delete/:id', isAuthenticated, async (req, res) => {
    try {
        const siteId = req.params.id;
        const site = await Site.findById(siteId);
  
        if (!site || site.user.toString() !== req.user._id.toString()) {
            return res.status(403).send('You are not authorized to delete this site.');
        }
  
        // Use deleteOne() to delete the site
        await Site.deleteOne({ _id: siteId });
  
        res.redirect('/earn'); // Redirect to the earnings page after deletion
    } catch (error) {
        console.error('Error deleting site:', error);
        res.status(500).send('Server error');
    }
  });
  
  
  app.post('/earn/edit/:id', upload.single('imageUrl'), async (req, res) => {
    const siteId = req.params.id;
    const { siteName, siteUrl, description, githubUrl, price } = req.body;
  
    try {
        let newImageUrl = req.body.oldImageUrl; // Keep the old image if no new one is uploaded
        let oldImagePublicId = req.body.oldImagePublicId;
  
        // If a new image is uploaded, upload it to Cloudinary
        if (req.file) {
            const result = await cloudinary.uploader.upload(req.file.path);
            newImageUrl = result.secure_url; // Cloudinary URL of the new image
            console.log("New Image URL from Cloudinary: ", newImageUrl); // Log the new image URL
            
            // Delete the old image if a new one is uploaded
            if (oldImagePublicId) {
                await cloudinary.uploader.destroy(oldImagePublicId);
            }
        }
  
        // Update the site record in the database with the new image URL
        const updatedSite = await Site.findByIdAndUpdate(siteId, {
            siteName,
            siteUrl,
            description,
            githubUrl,
            price,
            image: { url: newImageUrl } // Correctly update image.url
        }, { new: true });  // `new: true` returns the updated document
  
        console.log("Updated Site: ", updatedSite); // Log the updated site document
  
        // Redirect to the "All Websites" page after the update is done
        res.redirect('/earn');  // Change this to the route where you list all websites
    } catch (error) {
        console.error(error);
        res.status(500).send('Error updating site');
    }
  });
  
  
  
  
  // Add new site for the user
  app.post('/earn', upload.single('imageUrl'), async (req, res) => {
    try {
        // Check if file is uploaded
        if (!req.file) {
            return res.status(400).send('No file uploaded');
        }
  
        // Upload image to Cloudinary
        const result = await cloudinary.uploader.upload(req.file.path);
  
        // Save the site data to the database
        const newSite = new Site({
            siteName: req.body.siteName,
            siteUrl: req.body.siteUrl,
            description: req.body.description,
            githubUrl: req.body.githubUrl,
            price: req.body.price,
            image: {
                url: result.secure_url,
                filename: result.public_id
            },
            user: req.user._id, // Assuming the user is logged in
        });
  
        await newSite.save();
  
        res.redirect('/all-websites'); // Redirect after saving
    } catch (err) {
        console.log(err);
        res.status(500).send('Error uploading site');
    }
  });
  
  // Update earnings for a site
  app.post('/update-earnings/:siteId', async (req, res) => {
    const { siteId } = req.params;
  
    try {
      const site = await Site.findById(siteId);
      if (!site) {
        req.flash('error', 'Site not found');
        return res.redirect('/earn');
      }
  
      // Increase earnings by 5 (as an example, this can be modified)
      site.earnings += 5;
      await site.save();
  
      req.flash('success', 'Earnings updated!');
      res.redirect('/earn');
    } catch (err) {
      console.log(err);
      req.flash('error', 'Error updating earnings');
      res.redirect('/earn');
    }
  });
  
  app.post('/order', async (req, res) => {
    const { siteName, siteUrl, githubUrl, userName } = req.body;
  
    // Set up the email details
    const mailOptions = {
      from: 'your-email@gmail.com', // Your email address (sender)
      to: 'raghavrock098@gmail.com', // Recipient email address (your email)
      subject: 'New Order Request',
      html: `
          <h3>New Order Request</h3>
          <p><strong>User:</strong> ${userName}</p>
          <p><strong>Site Name:</strong> ${siteName}</p>
          <p><strong>Site URL:</strong> <a href="${siteUrl}" target="_blank">${siteUrl}</a></p>
          <p><strong>GitHub URL:</strong> <a href="${githubUrl}" target="_blank">${githubUrl}</a></p>
      `
    };
  
    try {
      // Send the email
      await transporter.sendMail(mailOptions);
      
      // Redirect to homepage after sending the order request
      res.redirect('/?orderSuccess=true');  // Redirects to the homepage (assuming it is at the root '/')
      
    } catch (error) {
      console.error('Error sending email:', error);
      res.status(500).send('Error sending email');
    }
  });
  
  
  // Logout route
  app.get('/logout', (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).send('Error logging out');
      }
      res.redirect('/'); // Redirect to home page after logout
    });
  });
  
  app.get("/about",(req,res)=>{
    res.render("about.ejs");
  });
  
  // Middleware to check if the user is authenticated
  function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.redirect('/login');
  }
  
  // Nodemailer transport configuration (for sending emails)
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'gamec8821@gmail.com', 
      pass: 'pgaf wxxo semj zzru',     // Store password in environment variable
    },
  });
  
  // Required modules
  
  // Function to send an email notification
  app.post('/send-email', async (req, res) => {
    const { freelancerEmail, contractDetails } = req.body;
  
    // Log the request body for debugging
    console.log('Received body:', req.body);
  
    if (!contractDetails || !contractDetails.paymentAmount || !contractDetails.employerAddress) {
      return res.status(400).send({ error: 'Contract details are missing or incomplete.' });
    }
  
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'gamec8821@gmail.com', // Replace with your email
        pass: 'pgaf wxxo semj zzru', // Replace with your app password
      },
    });
  
    const mailOptions = {
      from: 'gamec8821@gmail.com',
      to: freelancerEmail,
      subject: 'New Freelance Contract Request',
      text: `A new contract has been created for you by the employer.
             Contract details:
             - Payment Amount: ${contractDetails.paymentAmount} ETH
             - Employer Address: ${contractDetails.employerAddress}
             Please review and sign the contract in the application.`,
    };
  
    try {
      await transporter.sendMail(mailOptions);
      console.log('Email sent successfully to:', freelancerEmail);
      res.status(200).send({ message: 'Email sent successfully!' });
    } catch (error) {
      console.error('Error sending email:', error);
      res.status(500).send({ error: 'Failed to send email: ' + error.message });
    }
  });
  
  app.get('/scratch', async (req, res) => {
    const jobs = [
      { title: 'Software Engineer', company: 'Google', location: 'New York' },
      { title: 'Frontend Developer', company: 'Microsoft', location: 'San Francisco' },
    ];
  
    // Render the scratch.ejs view and pass the 'jobs' data
    res.render('scratch', { jobs: jobs });
  });
  
  // Route for `/search` - Fetch jobs based on skill
  app.get('/search', async (req, res) => {
    const skill = req.query.skill;
    if (!skill) {
      console.log("No skill provided, redirecting to /scratch");
      return res.redirect('/scratch'); // Redirect to /scratch if no skill is provided
    }
  
    try {
      console.log(`Fetching jobs for skill: ${skill}`);
  
      // Fetch job listings from LinkedIn, Unstop, and Google
      const linkedInJobs = await scrapeLinkedInJobs(skill);
      const unstopJobs = await fetchUnstopJobs(skill) || []; // Ensure unstopJobs is always an array
      const googleJobs = await fetchGoogleJobs(skill) || []; // Ensure googleJobs is always an array
  
      console.log('LinkedIn Jobs:', linkedInJobs);
      console.log('Unstop Jobs:', unstopJobs);
      console.log('Google Jobs:', googleJobs);
  
      // Combine all job listings
      const allJobs = [...linkedInJobs, ...unstopJobs, ...googleJobs];
  
      console.log('Combined Jobs:', allJobs); // Log the combined jobs for debugging
  
      // Render the scratch.ejs view and pass the combined jobs
      res.render('scratch', { jobs: allJobs, skill: skill });
    } catch (error) {
      console.error('Error in search:', error);
      res.render('scratch', { jobs: [], skill: skill }); // Render scratch with empty jobs array in case of error
    }
  });
  
  app.post('/payment', (req, res) => {
    res.render('payment');
  });
  
  app.post('/deposit', async (req, res) => {
    const { amount } = req.body;
  
    if (amount <= 0) {
        return res.status(400).send('Amount must be greater than zero');
    }
  
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(401).send('Unauthorized');
        }
  
        // Deposit the money into the user's wallet
        user.wallet += amount;
        await user.save();
  
        res.redirect('/wallet');  // Redirect to wallet page after deposit
    } catch (error) {
        console.error('Error depositing money:', error);
        res.status(500).send('Failed to deposit money');
    }
  });
  
  app.get('/success', async (req, res) => {
    const sessionId = req.query.session_id;
    const amount = req.query.amount;
  
    console.log('Session ID:', sessionId);  // Debugging log
    console.log('Amount:', amount);  // Debugging log
  
    if (!sessionId || !amount) {
        return res.status(400).send('Session ID or amount not provided');
    }
  
    try {
        // Retrieve the session from Stripe
        const session = await stripe.checkout.sessions.retrieve(sessionId);
  
        if (session.payment_status === 'paid') {
            // Payment successful
            const totalAmount = session.amount_total / 100; // Convert from paise to INR
            // Here, you would update the user's wallet balance in your database or session
            // For demonstration, we'll simply send a success message with the updated balance.
  
            // Redirect the user back to the wallet page and update the balance
            res.redirect(`http://localhost:8080/wallet?balance=${totalAmount}`);
        } else {
            res.send('Payment failed or was not completed');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Error verifying payment');
    }
  });
  
  
  // Cancel route for canceled payments
  app.get('/cancel', (req, res) => {
    res.send('Payment was canceled.');
  });
  
  app.post('/withdraw', async (req, res) => {
    const { amount } = req.body;
  
    if (amount <= 0) {
        return res.status(400).send('Amount must be greater than zero');
    }
  
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(401).send('Unauthorized');
        }
  
        if (user.wallet < amount) {
            return res.status(400).send('Insufficient balance');
        }
  
        // Withdraw the money from the user's wallet
        user.wallet -= amount;
        await user.save();
  
        res.redirect('/wallet');  // Redirect to wallet page after withdrawal
    } catch (error) {
        console.error('Error withdrawing money:', error);
        res.status(500).send('Failed to withdraw money');
    }
  });
  
  app.get('/create-checkout-session', async (req, res) => {
    const { amount } = req.query;
  
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [
                {
                    price_data: {
                        currency: 'inr',
                        product_data: {
                            name: 'Wallet Deposit',
                        },
                        unit_amount: amount * 100, // Amount in paise (smallest currency unit)
                    },
                    quantity: 1,
                },
            ],
            mode: 'payment',
            success_url: `http://localhost:8080/success?session_id={CHECKOUT_SESSION_ID}&amount=${amount}`,
            cancel_url: 'http://localhost:8080/cancel',
        });
  
        res.json({ url: session.url });
    } catch (error) {
        console.error(error);
        res.status(500).send('Error creating checkout session');
    }
  });
  
  
  
  // Show wallet page with balance
  app.get('/wallet', async (req, res) => {
    try {
        // Fetch any user's wallet balance (Example: First user in DB)
        const user = await User.findOne(); // Modify this logic as needed
        if (!user) {
            return res.status(404).send('User not found');
        }
  
        res.render('js', { balance: user.wallet });  // Render wallet.ejs with balance
    } catch (error) {
        console.error('Error fetching wallet balance:', error);
        res.status(500).send('Failed to fetch wallet balance');
    }
  });
  
  app.post('/login', async (req, res) => {
    const { email, password } = req.body;
  
    try {
        const user = await User.findOne({ email });
        if (!user || user.password !== password) {
            return res.status(401).send('Invalid email or password');
        }
  
        req.session.userId = user._id;  // Store user ID in session
        res.redirect('/wallet');  // Redirect to wallet after login
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).send('Internal Server Error');
    }
  });
  
  app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).send('Logout Failed');
        }
        res.redirect('/login');
    });
  });
  
  
  // Start the server
  app.listen(8080, () => {
    console.log("Server is running on http://localhost:8080");
  });
  

// Start Server
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
