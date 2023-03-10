import express from "express"
const app = express()
import dotenv from 'dotenv'
dotenv.config()
import cors from "cors"
import cookieParser from "cookie-parser"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import validator from "validator"
import bodyParser from 'body-parser'
import nodemailer from "nodemailer"
import multer from "multer"
import { ref, uploadBytes, getDownloadURL } from "firebase/storage"
import admin from "firebase-admin"
import axios from "axios"
const PORT = process.env.PORT
const router = express.Router()

import storage from './config/firebase.js';

const upload = multer({ storage: multer.memoryStorage() });
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(bodyParser.json());


import { getAllDoctor, doctorSignup,getDoctorById, login, logout, editDoc, docSched, getDoctorAppointments, 
  patientSignup, patientLogin, patientHealth, pharmacySignup, pharmacyAdmin, pharmacyAdminLogin, 
  saveImageUrlToDatabase, getOTP, deleteOTP, checkRejectedDocument, uploadNewDocument, authenticateAdmin, 
  acceptOrDeclineDoctor, getAllDoctorDocument, docServiceFee
  } from './database.js'

app.get('/', (req,res)=>{
   res.send("Hello world")

})

app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const admin = await authenticateAdmin(username, password);
  if (admin.error) {
    res.status(401).json(admin.error);
  }else {
    res.json(admin);
  }
});

app.get('/getAllDoctor', async (req,res)=>{
    const post = await getAllDoctor()
    res.send(post)
})

app.get('/getAllDoc', async (req,res)=>{
    const post = await getAllDoctorDocument()
    res.send(post)
})

app.get('/getAllDocById/:id', async (req,res)=>{
  const id = req.params.id
    const post = await getAllDoctorDocument(id)
    res.send(post)
})

app.get('/getDoctorById/:id', async (req,res)=>{
    const id = req.params.id
    const pos = await getDoctorById(id)
    res.send(pos)
})

app.post("/doctorSignup", async (req, res) =>{
    // const id = req.body.id;
    try {
        const {FirstName, SurName, Email, PhoneNumber, Password, ConfirmPassword} = req.body;
               
       if(!validator.isEmail(Email)){
            return res.status(400).json({ message: 'Invalid email address' });
        }

        if (Password !== ConfirmPassword) {
          return res.status(400).json({ message: 'Passwords do not match' });
        }

     const hashedPassword = await bcrypt.hash(Password, 10);
        
    const newUser = await doctorSignup(FirstName, SurName, Email, PhoneNumber, hashedPassword, ConfirmPassword)
    if (newUser.error) {
      console.log(newUser.error);
      return res.status(400).json({ error: newUser.error });
    }
    const token = jwt.sign({ Name: newUser.FirstName, Email: newUser.Email, id: newUser.DoctorId }, process.env.JWT_SECRET);
    res.status(201).json({ message: "User created", token, email: Email});
    // res.redirect(`/verify-otp?email=${Email}`);
    // res.status(201).send(reg)
    } catch (error) {
        console.log(error);
       return res.status(500).json({ message: "Error creating user" });
    }
})

app.post('/verify-otp', async (req, res) => {
  const { Email, otp } = req.body;

  try {
    // TODO: Retrieve the OTP from the database or cache
    const savedOTP = await getOTP(Email);

     // Compare the received OTP with the saved one
    if (otp === savedOTP) {
      await deleteOTP(Email);

      res.json({ message: 'OTP verified successfully' });
    } else {
      res.status(400).json({ message: 'Invalid OTP' });
    }
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ message: 'Error verifying OTP' });
  }
});

app.post("/resend-otp", async (req, res) =>{
    const {Email} = req.body
    try {
          const  token = await getOTP(Email)
       if (token.error) {
        return res.status(400).json({ error: token.error });
       }
       res.json({ message: 'OTP resend successfully', token: token });
    } catch (error) {
      res.status(500).json({ message: 'Error resending OTP' });
    }
})

app.post("/login", async (req, res) =>{
    const { Email, Password } = req.body;
   try {
    const loginData = await login(Email, Password);
    if (loginData.error) {
      res.status(401).json(loginData.error);
    } else {
      res.json(loginData);
    }
   } catch (error) {
    console.log(error);
   }
});

app.post("/logout", async (req, res) => {
    try {
        const { DoctorId } = req.body;
        const logoutUser = await logout(DoctorId)
        if (logoutUser.error) {
          return res.status(500).json({ message: logoutUser.error });
        }
        res.json({ message: logoutUser.message });
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: "An error occurred while logging out" });
    }
});

app.post('/uploadDoctorDocument', upload.single('image'), async (req, res) => {
  const { DoctorId, DocumentName } = req.body;

  try {
    // Check if the doctor can upload a new document
    const canUpload = await checkRejectedDocument(DoctorId);
    if (!canUpload.success) {
      return res.status(400).json({ message: 'Please wait for 10 days from the date of the last rejection.' });
    }

    // Check if a file was uploaded
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    // Upload file to Firebase Storage
    const fileName = `${Date.now()}_${req.file.originalname}`;
    const bucketRef = ref(storage, process.env.Bucket_url);
    const fileRef = ref(bucketRef, fileName);
    await uploadBytes(fileRef, req.file.buffer, {
      contentType: req.file.mimetype,
    });

    // Get download URL from Firebase Storage
    const DocumentUrl = await getDownloadURL(fileRef);

    // Upload document to the database
    const isUploaded = await uploadNewDocument(DoctorId, DocumentUrl, DocumentName);
    if (isUploaded) {
      res.status(200).json({ message: 'Document uploaded successfully' });
    } else {
      res.status(500).json({ message: 'An error occurred while uploading the document' });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: 'An error occurred' });
  }
});


app.post('/acceptOrDeclineDoctor', async (req, res) => {
  const { DoctorId, IsApproved } = req.body;
  
  try {
    const result = await acceptOrDeclineDoctor(DoctorId, IsApproved);
    res.status(200).send(result);
  } catch (error) {
    console.log(error);
    res.status(500).send({ message: 'An error occurred while accepting or declining the doctor' });
  }
});


app.post("/editdoctor/:id", upload.single('image'), async (req, res) => {
    try {
      const id = req.params.id;
      if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
      }

       // Upload file to Firebase Storage
       const fileName = `${Date.now()}_${req.file.originalname}`;
       const bucketRef = ref(storage, process.env.Bucket_url);
       const fileRef = ref(bucketRef, fileName);
       await uploadBytes(fileRef, req.file.buffer, {
         contentType: req.file.mimetype,
       });

        // Get download URL from Firebase Storage
      const ImageUrl = await getDownloadURL(fileRef);

      const {Gender ,FirstName, SurName,MiddleName, AboutMe, Address,
        Postcode, PhoneNumber,Qualification, Country, State, City, DateOfBirth} = req.body;
        
      await editDoc(id, Gender, FirstName, SurName,MiddleName, AboutMe, Address,
        Postcode, PhoneNumber,Qualification, ImageUrl, Country, State, City, DateOfBirth);
      res.json({ message: 'updated successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'An error occurred while updating the doctor details' });
    }
  });

  app.post('/upload', upload.single('image'), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
      }
  
      // Upload file to Firebase Storage
      const fileName = `${Date.now()}_${req.file.originalname}`;
      const bucketRef = ref(storage, process.env.Bucket_url);
      const fileRef = ref(bucketRef, fileName);
      await uploadBytes(fileRef, req.file.buffer, {
        contentType: req.file.mimetype,
      });
  
  
      // Get download URL from Firebase Storage
      const url = await getDownloadURL(fileRef);
  
      // Save URL to MySQL
      // const text = req.body.text;
       await saveImageUrlToDatabase(url).then(() => {
        console.log('Image URL saved to database');
      })
      .catch((error) => {
        console.error('Error saving image URL to database:', error);
      });
  
      return res.status(200).json({ message: 'File uploaded successfully' });
    } catch (error) {
      console.error('Error uploading file to Firebase Storage:', error);
      return res.status(500).json({ message: 'Error uploading file to Firebase Storage' });
    }
  });
  
app.post("/doctor_service_fee", async (req, res) =>{

  const { DoctorId, Service, Description, Rate, ServiceCharge } = req.body
  try {
     await docServiceFee(DoctorId, Service, Description, Rate, ServiceCharge)
     res.json({message: 'Appointment successfully booked'})
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Error " });
  }
})

app.post("/book_appointment", async (req, res) =>{

  const { DoctorId, Days, FromTimeOfDay, ToTimeOfDay } = req.body
  try {
     await docSched(DoctorId, Days, FromTimeOfDay, ToTimeOfDay)
     res.json({message: 'Appointment successfully booked'})
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Error " });
  }
})

app.get("/appointments/:DoctorId", async (req, res) => {
  const DoctorId = req.params.DoctorId;
  try {
    const appointments = await getDoctorAppointments(DoctorId);
    res.json(appointments);
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Error" });
  }
});


app.post("/patientSignup", async (req, res) =>{
  // const id = req.body.id;
  try {
      const {FirstName, SurName, Email, PhoneNumber, Password} = req.body;
             
     if(!validator.isEmail(Email)){
          return res.status(400).json({ message: 'Invalid email address' });
      }

   const hashedPassword = await bcrypt.hash(Password, 10);
      
  const newUser = await patientSignup(FirstName, SurName, Email, PhoneNumber, hashedPassword)

 if (newUser.error) {
    return res.status(400).json({ error: newUser.error });
  }
  else{
    const token = jwt.sign({ Name: newUser.FirstName, Email: newUser.Email, id: newUser.PatientId }, process.env.JWT_SECRET);
    res.status(201).json({ message: "User created", token});
  }
  // res.status(201).send(reg)
  } catch (error) {
      console.log(error);
     return res.status(500).json({ message: "Error creating user" });
  }
})

app.post("/patientlogin", async (req, res) =>{
  const { Email, Password } = req.body;
  try {
    const loginData = await patientLogin(Email, Password);
    if (loginData.error) {
      return res.status(400).json({ error: loginData.error });
    } else {
      res.json(loginData);
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/patient_health", async (req, res) =>{

  const { PatientId } = req.body
  try {
     await patientHealth(PatientId)
     res.json({message: 'successfully'})
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Error " });
  }
})

app.post("/pharmacy", async (req, res) =>{
  try {
      const {PharmacyName, PharmacyAddress, PharmacyEmail, PharmacyPhone} = req.body;
             
     if(!validator.isEmail(PharmacyEmail)){
          return res.status(400).json({ message: 'Invalid email address' });
      }
      
  const newUser = await pharmacySignup(PharmacyName, PharmacyAddress, PharmacyEmail, PharmacyPhone)

 if (newUser.error) {
    return res.status(400).json({ error: newUser.error });
  }
  else{
    res.status(201).json({Id: newUser.PharmacyId, message: "successful register"});
  }
  } catch (error) {
      console.log(error);
     return res.status(500).json({ message: "Error creating user" });
  }
})

app.post("/pharmacyAd", async (req, res) =>{
  try {

    const { FirstName, SurName, Email, PhoneNumber, PharmacyId, Password } = req.body
    if(!validator.isEmail(Email)){
      return res.status(400).json({ message: 'Invalid email address' });
  }
  const hashedPassword = await bcrypt.hash(Password, 10);
   const newUser = await pharmacyAdmin(FirstName, SurName, Email, PhoneNumber, PharmacyId, hashedPassword)
   if (newUser.error) {
    console.log(PharmacyId, Password);
    return res.status(400).json({ error: newUser.error });
  }
    else{
      const token = jwt.sign({ Name: newUser.FirstName, Email: newUser.Email, id: newUser.Pharmaceutical_AdminId }, process.env.JWT_SECRET);
      res.status(201).json({ message: "User created", token});
    }
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Error " });
  }
})

app.post("/pharmacyAdLogin", async (req, res) =>{
  const { Email, Password } = req.body;
  const loginData = await pharmacyAdminLogin(Email, Password);
  if (loginData.error) {
    return res.status(400).json({ error: loginData.error });
  } else {
    res.json(loginData);
  }
});







app.listen(PORT, ()=> console.log(`app on port ${PORT}`));














// app.post('/send-message', async (req, res) => {
//   try {
//     const recipient = req.body.recipient;
//     const mailFrom = 'Grapple';
//     const subject = 'Verify';
//     const randomNumber = Math.floor(100000 + Math.random() * 900000).toString();
//     const response = await axios.post('http://profitmax-001-site8.ctempurl.com/api/Account/general_email_sending', {
//       recipient: recipient,
//       mailFrom: mailFrom,
//       subject: subject,
//       message: randomNumber
//     });

//     // Check response status code
//     if (response.status === 200) {
//       return res.status(200).json({ message: 'Message sent successfully' });
//     } else {
//       return res.status(500).json({ message: 'Failed to send message' });
//     }
//   } catch (error) {
//     console.error('Error sending message:', error);
//     return res.status(500).json({ message: 'Error sending message' });
//   }
// });




// app.post("/update_appointment_status", async (req, res) => {
//   const { AppointId, status } = req.body;
//   try {
//     await updateAppointStatus(AppointId, status);
//     res.json({ message: 'Appointment status updated successfully' });
//   } catch (error) {
//     console.log(error);
//     return res.status(500).json({ message: 'Error updating appointment status' });
//   }
// });