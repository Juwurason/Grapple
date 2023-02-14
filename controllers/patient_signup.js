import express from "express"
import dotenv from 'dotenv'
import bodyParser from 'body-parser'
dotenv.config()

const db = require('../database')

var router = express.Router();

router.use(bodyParser.json());

 router.post("/patientSignup", async (req, res) =>{
    // const id = req.body.id;
    try {
        const {FirstName, SurName, Email, PhoneNumber, Password} = req.body;
               
       if(!validator.isEmail(Email)){
            return res.status(400).json({ message: 'Invalid email address' });
        }
  
     const hashedPassword = await bcrypt.hash(Password, 10);
        
    const newUser = await db.patientSignup(FirstName, SurName, Email, PhoneNumber, hashedPassword)
    const token = jwt.sign({ Name: newUser.FirstName, Email: newUser.Email, id: newUser.PatientId }, process.env.JWT_SECRET);
    res.status(201).json({ message: "User created", token});
    // res.status(201).send(reg)
    } catch (error) {
        console.log(error);
       return res.status(500).json({ message: "Error creating user" });
    }
  })

  module.exports = router;

  module.exports.patientSignup = patientSignup;