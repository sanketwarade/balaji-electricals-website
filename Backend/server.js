const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const csrf = require('csrf');  // CSRF token library
const sgMail = require('@sendgrid/mail');  // Import SendGrid
const cors = require('cors');
const validator = require('validator');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet'); // New: Secure HTTP headers
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Define the rate limit rule
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: 'Too many requests from this IP, please try again after 15 minutes.',
});

// Apply to all routes
app.use(limiter);
// Enable trust proxy in Express
app.set('trust proxy', 1); // This allows Express to trust the X-Forwarded-For header

app.use(bodyParser.json());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(helmet());

const tokens = new csrf();

// Allow requests only from your frontend
const corsOptions = {
  origin: 'https://balajielectricals.netlify.app',  // Allow your frontend
  methods: ['GET', 'POST'],  // Allow specific methods
  allowedHeaders: ['Content-Type', 'X-CSRF-TOKEN'],  // Allow headers
  credentials: true  // Allow cookies or sessions to be sent
};

app.use(cors(corsOptions));

// MySQL Database Connection
const pool = mysql.createPool({
  host: process.env.DB_HOST, // From environment variables
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test connection on startup
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Database Connection Failed:', err);
  } else {
    console.log('Connected to Database');
    connection.release();
  }
});

// Create the MySQL session store using the pool
const sessionStore = new MySQLStore({}, pool);

module.exports = pool;  // Export pool directly



app.use(session({
  secret: process.env.SESSION_SECRET,  // Replace with a secure secret
  resave: false,
  store: sessionStore,
  saveUninitialized: false,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24,  // Session valid for 1 day
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',  // Secure cookie in production
    sameSite: 'lax'  // Ensure CSRF cookie can work cross-origin
  }
}));

// CORS Configuration
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'https://balajielectricals.netlify.app');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-TOKEN');
  next();
});

// CSRF Token Generation Endpoint
app.get('/csrf-token', (req, res) => {
  const csrfSecret = tokens.secretSync();
  const csrfToken = tokens.create(csrfSecret);
  req.session.csrfSecret = csrfSecret;
  
  res.json({ csrfToken });
});





// Email Setup using environment variables
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

app.post('/submit-solutionform', [
  body('name').trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('phone').isLength({ min: 10, max: 10 }).isNumeric().trim(),
  body('description').optional().escape(),
  body('machine-type').optional().escape(),
], (req, res) => {
  const csrfToken = req.headers['x-csrf-token'];
  const csrfSecret = req.session.csrfSecret;

  if (!tokens.verify(csrfSecret, csrfToken)) {
    // Process form data
        // Send email and insert data into the database
        res.status(403).json({ error: 'Invalid CSRF token' });
    }

  console.log('Form Data:', req.body);

  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }

  // Destructure only once to avoid redeclaration issues
  const { formType, name, email, phone, 'machine-type': machineType, description } = req.body;

  // Ensure that machineType is not undefined or null
  if (!machineType) {
    return res.status(400).send({ success: false, message: 'Machine Type is required' });
  }

  const query = `
      INSERT INTO custom_solutions 
      (form_type, name, email, phone, machine_type, description) 
      VALUES (?, ?, ?, ?, ?, ?)
  `;
  pool.query(query, [form_Type, name, email, phone, machine_type, description], (err, result) => {
    if (err) {
        console.error('Error inserting data:', err)
    }

    const userMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,  // Must be verified on SendGrid
      to: email, 
      subject: 'Custom Solution Request Received',
      text: `Hello ${name},\n\nThank you for requesting a custom solution.\nWe will get back to you shortly.`
    };

    const adminMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: process.env.ADMIN_EMAIL,  
      subject: 'New custom solution Request',
      text: `New Custom Solution request received:\n\nName: ${name}\nDescription: ${description}\nPhone: ${phone}\nEmail: ${email}\nMachine Type: ${machineType || 'N/A'}`
    };

    // Send emails
    sgMail
      .send(userMail)
      .then(() => {
        console.log('Confirmation email sent to user');
      })
      .catch((error) => {
        console.error('Error sending email to user:', error);
      });

    sgMail
      .send(adminMail)
      .then(() => {
        console.log('Notification email sent to admin');
      })
      .catch((error) => {
        console.error('Error sending email to admin:', error);
      });
      res.status(200).send({ success: true, message: 'Form submitted successfully!' });
  });
});





// POST endpoint to handle form submission (Quote Form)
app.post('/submit-quoteForm', [
  body('name').trim().escape().isLength({ min: 2, max: 50 }),
  body('email').isEmail().normalizeEmail(),
  body('contact').isMobilePhone('en-IN'),
  body('message').trim().escape().isLength({ min: 10, max: 200 }),
], 

  (req, res) => {
    const { name, company, contact, email, machines, message } = req.body;
    // Log received data for debugging
    console.log('Received Data:', req.body);  // Log received data on backend
  // Ensure company is not undefined or null
  const companyValue = company || ''; // Default to empty string if company is undefined
   // Initialize an error message array
   let errors = [];
   // *Validate Name*
   if (!name || name.trim() === '') {
    errors.push('Name is required.');
  } else if (!validator.isLength(name, { min: 2, max: 50 })) {
    errors.push('Name must be between 2 and 50 characters.');
  }

  // *Validate Email*
  if (!email || !validator.isEmail(email)) {
    errors.push('A valid email address is required.');
  }

  // *Validate Phone*
  if (!contact || !validator.isMobilePhone(contact, 'en-IN')) {
    errors.push('A valid 10-digit phone number is required.');
  }

  // *Validate Subject*
  if (!message || message.trim().length < 10 || message.trim().length > 200) {
    errors.push('message must be between 10 and 200 characters.');
  }

  // If there are validation errors, return them
  if (errors.length > 0) {
    return res.status(400).json({ success: false, errors });
  }

  // Sanitize Inputs
  const sanitizedInputs = {
    name: validator.escape(name),
    email: validator.escape(email),
    phone: validator.escape(contact),
    message: validator.escape(message),
  };

  // Save data to MySQL
  const query = 'INSERT INTO quote_requests (name, company, contact, email, machines, message) VALUES (?, ?, ?, ?, ?, ?)';
  const values = [sanitizedInputs.name, companyValue, sanitizedInputs.phone, sanitizedInputs.email, JSON.stringify(machines), sanitizedInputs.message];

  pool.query(query, values, (err, result) => {
    if (err) {
      console.error('Error inserting data into database:', err);
      return res.status(500).json({ message: 'Error saving data to database' });
    }

    // Send email to user (confirmation)
    const userMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: sanitizedInputs.email,
      subject: 'Quote Request Received',
      text: `Hello ${name},\n\nThank you for requesting a quote. Here are the details we received:\n\nMachines/Parts: ${machines.join(', ')}\nMessage: ${message}\n\nWe will get back to you shortly.`,
    };

    // Send email to admin (quote details)
    const adminMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: process.env.ADMIN_EMAIL,
      subject: 'New Quote Request',
      text: `New quote request received:\n\nName: ${name}\nCompany: ${companyValue}\nContact: ${contact}\nEmail: ${email}\nMachines/Parts: ${machines.join(', ')}\nMessage: ${message}`,
    };

    // Send emails
    sgMail.send(userMail).then(() => {
      console.log('Confirmation email sent to user');
    }).catch((error) => {
      console.error('Error sending email to user:', error);
    });

    sgMail.send(adminMail).then(() => {
      console.log('Notification email sent to admin');
    }).catch((error) => {
      console.error('Error sending email to admin:', error);
    });

    // Send success response
    res.status(200).json({ message: 'Quote request submitted successfully' });
  });
  });

// POST endpoint to handle form submission (Enquiry Form)
app.post('/submit-Enquiryform', [
  body('name').trim().escape().isLength({ min: 2, max: 50 }),
  body('email').isEmail().normalizeEmail(),
  body('phone').isMobilePhone('en-IN'),
  body('subject').trim().escape().isLength({ min: 10, max: 200 }),
],  (req, res) => {
  const { name, email, phone, subject } = req.body;
  console.log('Request received:', req.body);

  let errors = [];

  // *Validate Name*
  if (!name || name.trim() === '') {
    errors.push('Name is required.');
  } else if (!validator.isLength(name, { min: 2, max: 50 })) {
    errors.push('Name must be between 2 and 50 characters.');
  }

  // *Validate Email*
  if (!email || !validator.isEmail(email)) {
    errors.push('A valid email address is required.');
  }

  // *Validate Phone*
  if (!phone || !validator.isMobilePhone(phone, 'en-IN')) {
    errors.push('A valid 10-digit phone number is required.');
  }

  // *Validate Subject*
  if (!subject || subject.trim().length < 10 || subject.trim().length > 200) {
    errors.push('Subject must be between 10 and 200 characters.');
  }

  // If there are validation errors, return them
  if (errors.length > 0) {
    return res.status(400).json({ success: false, errors });
  }



  // Sanitize Inputs
  const sanitizedInputs = {
    name: validator.escape(name),
    email: validator.escape(email),
    phone: validator.escape(phone),
    subject: validator.escape(subject),
  };

  // Save data to MySQL
  const query = 'INSERT INTO enquiries (name, email, phone, subject) VALUES (?, ?, ?, ?)';
  const values = [sanitizedInputs.name, sanitizedInputs.email, sanitizedInputs.phone, sanitizedInputs.subject];

  pool.query(query, values, (err, result) => {
    if (err) {
      console.error('Error inserting data:', err);
      return res.status(500).send('Error saving data');
    }

    // Send confirmation email to the user
    const userMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: sanitizedInputs.email,
      subject: 'Thank you for your enquiry!',
      text: `Dear ${name},\n\nThank you for reaching out to BALAJI ELECTRICALS. We will get back to you soon.\n\nBest regards,\nBALAJI ELECTRICALS`,
    };

    // Send notification email to admin
    const adminMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: process.env.ADMIN_EMAIL,
      subject: 'New Enquiry Received',
      text: `New enquiry from ${name}.\n\nDetails:\nName: ${name}\nEmail: ${email}\nPhone: ${phone}\nSubject: ${subject}`,
    };

    // Send emails
    sgMail.send(userMail).then(() => {
      console.log('Confirmation email sent to user');
    }).catch((error) => {
      console.error('Error sending email to user:', error);
    });

    sgMail.send(adminMail).then(() => {
      console.log('Notification email sent to admin');
    }).catch((error) => {
      console.error('Error sending email to admin:', error);
    });

    // Send success response
    res.status(200).send('Enquiry submitted successfully');
  });
});
  
// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});




