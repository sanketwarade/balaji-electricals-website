const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const csrf = require('csrf');  // CSRF token library for forms
const sgMail = require('@sendgrid/mail');  // Import SendGrid
const cors = require('cors');
const validator = require('validator');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet'); // New: Secure HTTP headers
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const cron = require('node-cron');
const moment = require('moment'); // To handle date and time more easily
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(helmet());// Secure HTTP headers
app.set('trust proxy', 1); // This allows Express to trust the X-Forwarded-For header

// ------------------- RATE LIMITING --------------------
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 80, // Limit each IP to 100 requests per window
  message: 'Too many requests from this IP, please try again after 15 minutes.',
});
// Apply to all routes
app.use(limiter);

// ------------------- CORS --------------------
const corsOptions = {
  origin: 'https://balajielectricals.netlify.app',  // Allow your frontend
  methods: ['GET', 'POST'],  // Allow specific methods
  allowedHeaders: ['Content-Type', 'X-CSRF-TOKEN'],  // Allow headers
  credentials: true  // Allow cookies or sessions to be sent
};
app.use(cors(corsOptions));

// ------------------- STATIC FILES --------------------
// Serve static files from the Frontend directory
app.use(express.static(path.join(__dirname, '../Frontend')));

// ------------------- MYSQL CONNECTION --------------------
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

// ------------------- SESSION SETUP --------------------
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
    sameSite: 'None'    // Ensure CSRF cookie can work cross-origin
  }
}));


app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://balajielectricals.netlify.app');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-CSRF-TOKEN');
  next();
});

app.get('/', (req, res) => {
  res.send('Welcome to Balaji Electricals!');
});

// ------------------- CSRF SETUP --------------------
const tokens = csrf(); // Initialize CSRF token generation correctly

// CSRF Token Generation Endpoint
app.get('/csrf-token', (req, res) => {
  const csrfSecret = tokens.secretSync(); // Generate a new CSRF secret
  const csrfToken = tokens.create(csrfSecret); // Create the CSRF token

  // Store the CSRF secret in the session so it can be validated later
  req.session.csrfSecret = csrfSecret;

  // Respond with the CSRF token and the expiration time of the session cookie
  res.json({ csrfToken, expiresIn: req.session.cookie.maxAge / 1000 });
});

// Middleware to check if the site is in maintenance mode
app.use((req, res, next) => {
  const maintenanceMode = process.env.MAINTENANCE_MODE === 'FALSE';
  
  if (maintenanceMode) {
      // Corrected path to maintenance.html
      const maintenancePath = path.join(__dirname, '../Frontend', 'maintenance.html');
      console.log('Serving maintenance page from:', maintenancePath);
      
      if (fs.existsSync(maintenancePath)) {
          res.sendFile(maintenancePath);
      } else {
          console.error('Maintenance page not found at:', maintenancePath);
          res.status(404).send('Maintenance page not found');
      }
  } else {
      next(); // Proceed to other routes if not in maintenance mode
  }
});
// Email Setup using environment variables
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// POST endpoint to handle form submission (Quote Form) this is the form 3
app.post('/submit-quoteForm',[ //form 3
  body('name').trim().escape().isLength({ min: 3, max: 50 }),
  body('email').isEmail().normalizeEmail(),
  body('contact').isLength({ min: 10, max: 10 }).isNumeric().trim(),
  body('message').trim().escape().isLength({ min: 10, max: 100 }),
  body('company').trim().escape().isLength({min: 3, max: 50}),
  body('machines').trim().escape().isIn(['MIG Welding Machine', 'TIG Welding Machine', 'SPM Welding Machine', 'Rotary Positioner','X-Y Linear Slides','Spare Parts','Control Panels']) .withMessage('Invalid machine selection.')
], 
  (req, res) => {
    console.log('Form Data:', req.body);
    const csrfToken = req.headers['x-csrf-token'];
    const csrfSecret = req.session.csrfSecret;
    console.log('Received CSRF token:', csrfToken);  // Log received token
    console.log('Stored CSRF secret:', csrfSecret);  // Log stored token
  
  if (!csrfToken) {
    return res.status(400).json({ error: 'CSRF token missing' });
  }
  if (!csrfSecret || !tokens.verify(csrfSecret, csrfToken)) {
    console.log('CSRF verification failed');
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array());
    return res.status(400).json({ errors: errors.array() });
    }
    const { formType, name, company, contact, email, machines, message } = req.body;
    // Validate and process the data
    if (!name || !email || !contact || !company || !machines || !message) {
      return res.status(400).json({ error: 'All fields are required' });
  }
  // Ensure that machineType is not undefined or null
  if (!contact) {
    return res.status(400).send({ success: false, message: 'contact is required' });
  }
  // Sanitize Inputs
  const sanitizedInputs = {
    name: validator.escape(name),
    email: validator.escape(email),
    phone: validator.escape(contact),
    message: validator.escape(message),
    company:validator.escape(company)
  };

  // Save data to MySQL
  const query = 'INSERT INTO quote_requests (form_type, name, company, contact, email, machines, message) VALUES (?, ?, ?, ?, ?, ?, ?)';
  const values = [formType, sanitizedInputs.name, sanitizedInputs.company, sanitizedInputs.contact, sanitizedInputs.email, JSON.stringify(machines), sanitizedInputs.message];
 

  pool.execute(
    'INSERT INTO quote_requests (form_type, name, company, contact, email, machines, message) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [formType, name, company, contact, email, machines, message],
    (err, result) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      console.log('Data inserted into database:', result);

      // Send success response after successful insertion
    res.status(200).json({
      success: true,
      message: 'Quote Request Submitted Successfully!'
    });
    }
  );
    // Send email to user (confirmation)
    const userMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: sanitizedInputs.email,
      subject: 'Quote Request Received',
      text: `Hello ${sanitizedInputs.name},\n\nThank you for requesting a quote. Here are the details we received:\n\nMachines/Parts: ${machines.join(', ')}\nMessage: ${sanitizedInputs.message}\n\nWe will get back to you shortly.`,
      };
    // Send email to admin (quote details)
    const adminMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,
      to: process.env.ADMIN_EMAIL,
      subject: 'New Quote Request',
      text: `New quote request received:\n\nName: ${sanitizedInputs.name}\nCompany: ${sanitizedInputs.company}\nContact: ${sanitizedInputs.contact}\nEmail: ${sanitizedInputs.email}\nMachines/Parts: ${machines.join(', ')}\nMessage: ${sanitizedInputs.message}`,
      };
     // Send emails asynchronously
    Promise.all([sgMail.send(userMail), sgMail.send(adminMail)])
    .then(() => {
      console.log('Emails sent to user and admin');
    })
    .catch((error) => {
      console.error('Error sending emails:', error);
    });
}
);       
// ------------------- GENERIC ERROR HANDLER --------------------
  //post method  for custom-solution
app.post('/submit-solutionform', [
  body('name').trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('phone').isLength({ min: 10, max: 10 }).isNumeric().trim(),
  body('description').isLength({min:10, max:100}).trim(),
  body('machine-type').isLength({min:3, max:50}).trim(),
], (req, res) => {
  console.log('Form Data:', req.body);
  const csrfToken = req.headers['x-csrf-token'];
  const csrfSecret = req.session.csrfSecret;
  console.log('Received CSRF token:', csrfToken);  // Log received token
  console.log('Stored CSRF secret:', csrfSecret);  // Log stored token

if (!csrfToken) {
  return res.status(400).json({ error: 'CSRF token missing' });
}
if (!csrfSecret || !tokens.verify(csrfSecret, csrfToken)) {
  console.log('CSRF verification failed');
  return res.status(403).json({ error: 'Invalid CSRF token' });
}


  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }
  // Destructure only once to avoid redeclaration issues
  const { formType, name, email, phone,  'machine-type': machineType, description } = req.body;
  if (!name || !email || !phone || !machineType || !description) {
    return res.status(400).json({ error: 'All fields are required' });
}
  // Ensure that machineType is not undefined or null
  if (!machineType) {
    return res.status(400).send({ success: false, message: 'Machine Type is required' });
  }
  // Sanitize Inputs
  const sanitizedInputs = {
    name: validator.escape(name),
    email: validator.escape(email),
    phone: validator.escape(phone),
    subject: validator.escape(machineType),
    description: validator.escape(description)
  };
  const query = `'INSERT INTO custom_solutions (form_type, name, email, phone, machine_type, description) VALUES (?, ?, ?, ?, ?, ?);''
  `
  const values = [sanitizedInputs.name, sanitizedInputs.email, sanitizedInputs.phone, sanitizedInputs.machineType,sanitizedInputs.description];
  pool.execute(
    'INSERT INTO custom_solutions (form_type, name, email, phone, machine_type, description) VALUES (?, ?, ?, ?, ?, ?)',
    [formType, name, email, phone, machineType, description],
    (query, values,(err, result) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      console.log('Data inserted into database:', result);
    }
  )
  );
    const userMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,  // Must be verified on SendGrid
      to: sanitizedInputs.email, 
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
//post method  for custom-solution
app.post('/submit-solutionform', [
  body('name').trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('phone').isLength({ min: 10, max: 10 }).isNumeric().trim(),
  body('description').isLength({min:10, max:100}).trim(),
  body('machine-type').isLength({min:3, max:50}).trim(),
], (req, res) => {
  console.log('Form Data:', req.body);
  const csrfToken = req.headers['x-csrf-token'];
  const csrfSecret = req.session.csrfSecret;
  console.log('Received CSRF token:', csrfToken);  // Log received token
  console.log('Stored CSRF secret:', csrfSecret);  // Log stored token

if (!csrfToken) {
  return res.status(400).json({ error: 'CSRF token missing' });
}
if (!csrfSecret || !tokens.verify(csrfSecret, csrfToken)) {
  console.log('CSRF verification failed');
  return res.status(403).json({ error: 'Invalid CSRF token' });
}
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }
  // Destructure only once to avoid redeclaration issues
  const { formType, name, email, phone,  'machine-type': machineType, description } = req.body;
  if (!name || !email || !phone || !machineType || !description) {
    return res.status(400).json({ error: 'All fields are required' });
}
  // Ensure that machineType is not undefined or null
  if (!machineType) {
    return res.status(400).send({ success: false, message: 'Machine Type is required' });
  }
  // Sanitize Inputs
  const sanitizedInputs = {
    name: validator.escape(name),
    email: validator.escape(email),
    phone: validator.escape(phone),
    subject: validator.escape(machineType),
    description: validator.escape(description)
  };
  const query = `'INSERT INTO custom_solutions (form_type, name, email, phone, machine_type, description) VALUES (?, ?, ?, ?, ?, ?);''
  `
  const values = [sanitizedInputs.name, sanitizedInputs.email, sanitizedInputs.phone, sanitizedInputs.machineType,sanitizedInputs.description];
  pool.execute(
    'INSERT INTO custom_solutions (form_type, name, email, phone, machine_type, description) VALUES (?, ?, ?, ?, ?, ?)',
    [formType, name, email, phone, machineType, description],
    (query, values,(err, result) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      console.log('Data inserted into database:', result);
    }
  )
  );
    const userMail = {
      from: process.env.SENDGRID_SENDER_EMAIL,  // Must be verified on SendGrid
      to: sanitizedInputs.email, 
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


// POST endpoint to handle form submission (Enquiry Form)
app.post('/submit-Enquiryform', [
  body('name').trim().escape().isLength({ min: 2, max: 50 }),
  body('email').isEmail().normalizeEmail(),
  body('phone').isMobilePhone('en-IN'),
  body('subject').trim().escape().isLength({ min: 10, max: 200 }),
],  (req, res) => {
  console.log('Received Data:', req.body);
  const csrfToken = req.headers['x-csrf-token'];
    const csrfSecret = req.session.csrfSecret;
    console.log('Received CSRF token:', csrfToken);  // Log received token
    console.log('Stored CSRF secret:', csrfSecret);  // Log stored token
    console.log('Received CSRF token:', csrfToken);  // Log received token
  console.log('Stored CSRF secret:', csrfSecret); 
    
    if (!csrfToken) {
      return res.status(400).json({ error: 'CSRF token missing' });
    }
    
    if (!csrfSecret || !tokens.verify(csrfSecret, csrfToken)) {
      console.log('CSRF verification failed');
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    

    const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log('Validation Errors:', errors.array());
    return res.status(400).json({ errors: errors.array() });
  }
  
  const { formType, name, email, phone, subject } = req.body;

  // Sanitize Inputs
  const sanitizedInputs = {
    name: validator.escape(name),
    email: validator.escape(email),
    phone: validator.escape(phone),
    subject: validator.escape(subject),
  };

  
  // Save data to MySQL
  const query = 'INSERT INTO enquiries (form_type, name, email, phone, subject) VALUES (?, ?, ?, ?, ?)';
  const values = [sanitizedInputs.name, sanitizedInputs.email, sanitizedInputs.phone, sanitizedInputs.subject];

  pool.execute(
    'INSERT INTO enquiries (form_type, name, email, phone, subject) VALUES (?, ?, ?, ?, ?)',
    [formType, name, email, phone,  subject],
    (query, values,(err, result) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      console.log('Data inserted into database:', result);
    }
  )
  );

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

// Handle email subscription and notifications
app.post('/notify', async (req, res) => {
  const { email } = req.body;

  try {
    // Check if the email already exists
    const [rows, fields] = await pool.execute('SELECT * FROM emails WHERE email = ?', [email]);

    if (!Array.isArray(rows)) {
      throw new Error('Unexpected query result format.');
    }

    console.log('Query result:', rows);

    // If email already exists, return a response
    if (rows.length > 0) {
      return res.status(400).send('This email is already subscribed.');
    }

    // Insert email into the database
    const [insertResult] = await pool.execute('INSERT INTO emails (email) VALUES (?)', [email]);
    console.log('Data inserted into database:', insertResult);

    // Prepare and send email using SendGrid
    const msg = {
      to: email,
      from: process.env.ADMIN_EMAIL,
      subject: 'Website Maintenance Update',
      text: 'The website is now back online! Thank you for your patience.',
    };

    // Send email
    await sgMail.send(msg);
    console.log(`Email sent to ${email}`);

    // Respond to client
    res.status(200).send('Email sent and email saved successfully.');

  } catch (err) {
    // Handle errors
    console.error('Error:', err);
    res.status(500).send('Failed to save email or send notification.');
  }
});


// Calculate the date and time for the maintenance to end (3 days, 3 hours, 33 minutes, and 45 seconds from now)
const endTime = moment().add({ days: 3, hours: 3, minutes: 33, seconds: 45 }); // Set maintenance end time

// Convert the end time to cron format (rounded to the nearest minute)
const cronSchedule = `${endTime.minutes()} ${endTime.hours()} ${endTime.date()} ${endTime.month() + 1} *`; // cron expects months to be in 1-12 range

// Task to send emails to all subscribers when maintenance ends
cron.schedule(cronSchedule, async () => {
  console.log(`Sending emails at ${endTime.format('YYYY-MM-DD HH:mm:ss')}`);

  try {
    // Fetch all email addresses from the database
    const [results] = await pool.execute('SELECT email FROM emails');
    
    // Loop through each email and send an email via SendGrid
    for (let result of results) {
      const email = result.email;

      const msg = {
        to: email,
        from: process.env.ADMIN_EMAIL, // Replace with your email
        subject: 'Website Maintenance Update',
        text: 'The website is now back online! Thank you for your patience.',
      };

      try {
        await sgMail.send(msg);
        console.log(`Email sent to ${email}`);
      } catch (error) {
        console.error(`Error sending email to ${email}:`, error);
      }
    }
  } catch (err) {
    console.error('Error fetching emails from database:', err);
  }
});

// Endpoint to enable maintenance mode
app.post('/maintenance/on', (req, res) => {
  const envPath = path.join(__dirname, '../.env');
  const envData = fs.readFileSync(envPath, 'utf-8');
  const updatedEnv = envData.replace('MAINTENANCE_MODE=FALSE', 'MAINTENANCE_MODE=TRUE');
  fs.writeFileSync(envPath, updatedEnv);
  console.log('Maintenance mode enabled');
  res.status(200).send('Maintenance mode enabled');
});

// Endpoint to disable maintenance mode
app.post('/maintenance/off', (req, res) => {
  const envPath = path.join(__dirname, '../.env');
  const envData = fs.readFileSync(envPath, 'utf-8');
  const updatedEnv = envData.replace('MAINTENANCE_MODE=TRUE', 'MAINTENANCE_MODE=FALSE');
  fs.writeFileSync(envPath, updatedEnv);
  console.log('Maintenance mode disabled');
  res.status(200).send('Maintenance mode disabled');
});

// Endpoint to check the current maintenance mode status
app.get('/maintenance/status', (req, res) => {
  const envPath = path.join(__dirname, '../.env');
  const envData = fs.readFileSync(envPath, 'utf-8');
  const isMaintenanceMode = envData.includes('MAINTENANCE_MODE=TRUE');
  res.json({ status: isMaintenanceMode });
});


// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});




