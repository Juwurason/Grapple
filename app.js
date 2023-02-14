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
const PORT = process.env.PORT
const router = express.Router()

app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(bodyParser.json());

import {getpost, doctorSignup, getpos, login, logout,
   editDoc, docSched, getDoctorAppointments, patientSignup, getpo, patientLogin, patientHealth, 
   pharmacySignup, pharmacyAdmin, pharmacyAdminLogin
  } from './database.js'

app.get('/', (req,res)=>{
   
    res.send("hello world")
})

app.get('/post', async (req,res)=>{
    const post = await getpost()
    res.send(post)
})


app.get('/post/:id', async (req,res)=>{
    const id = req.params.id
    const pos = await getpos(id)
    res.send(pos)
})

// app.post("/register", async (req, res) =>{
//     try {
//   const {CompanyName, CompanyEmail, CompanyAddress, CompanyPhone, PackagesId} = req.body;

//    if(!validator.isEmail(CompanyEmail)){
//     return res.status(400).json({ message: 'Invalid email address' });
// }
//     const reg = await register(CompanyName, CompanyEmail, CompanyAddress, CompanyPhone, PackagesId)
//     const i = {id: reg.CompanyId}
//     // const comid = await getposts(CompanyId)
//     res.status(301).send({'message': i, 'url': '/companyadmin'})
//     // res.redirect(`/companyadmin`)
//     } catch (error) {
//         console.log(error);
//         return res.status(500).json({ message: "Error creating user" });
//     }
// })

app.post("/doctorSignup", async (req, res) =>{
    // const id = req.body.id;
    try {
        const {FirstName, SurName, Email, PhoneNumber, Password} = req.body;
               
       if(!validator.isEmail(Email)){
            return res.status(400).json({ message: 'Invalid email address' });
        }

     const hashedPassword = await bcrypt.hash(Password, 10);
        
    const newUser = await doctorSignup(FirstName, SurName, Email, PhoneNumber, hashedPassword)
    if (newUser.error) {
      return res.status(400).json({ error: newUser.error });
    }
    const token = jwt.sign({ Name: newUser.FirstName, Email: newUser.Email, id: newUser.DoctorId }, process.env.JWT_SECRET);
    res.status(201).json({ message: "User created", token});
    // res.status(201).send(reg)
    } catch (error) {
        console.log(error);
       return res.status(500).json({ message: "Error creating user" });
    }
})

app.post("/login", async (req, res) =>{
    const { Email, Password } = req.body;
    const loginData = await login(Email, Password);
    if (loginData.error) {
      res.status(401).json(loginData.error);
    } else {
      res.json(loginData);
    }
});

app.post("/logout", async (req, res) => {
    try {
        const { DoctorId } = req.body;
        const logoutUser = await logout(DoctorId)
        res.json({ message: "User logged out successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "An error occurred while logging out" });
    }
});

app.post("/editdoctor/:id", async (req, res) => {
    try {
      const id = req.params.id;
      // const id = Number(req.params.id);
      // const id = parseInt(req.params.id, 10);
      const {Gender ,FirstName, SurName,MiddleName, AboutMe, Address,
        Postcode, PhoneNumber,Qualification, ImageUrl, Country, State, City, DateOfBirth} = req.body;
        
      await editDoc(id, Gender, FirstName, SurName,MiddleName, AboutMe, Address,
        Postcode, PhoneNumber,Qualification, ImageUrl, Country, State, City, DateOfBirth);
      res.json({ message: 'details updated successfully' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'An error occurred while updating the doctor details' });
    }
  });
  
app.post("/book_appointment", async (req, res) =>{

  const { DoctorId, ScheDate, ScheTime } = req.body
  try {
     await docSched(DoctorId, ScheDate, ScheTime)
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
  const loginData = await patientLogin(Email, Password);
  if (loginData.error) {
    return res.status(400).json({ error: loginData.error });
  } else {
    res.json(loginData);
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