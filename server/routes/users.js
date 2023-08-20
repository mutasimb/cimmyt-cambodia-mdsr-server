const
  express = require("express"),
  { genSalt, hash, compare } = require("bcryptjs"),
  { verify } = require("jsonwebtoken"),

  { jwtSecret } = require("../config/keys.js"),

  authMiddleware = require("../middleware/auth.js"),
  createToken = require("../utils/token.js"),

  Users = require("../models/Users.js"),
  Fields = require("../models/Fields.js"),
  Machines = require("../models/Machines.js"),
  Services = require("../models/Services.js"),

  router = express.Router();


// @route    POST /api/users/token
// @desc     Check the token for the nuxt middleware
// @access   Public
router.get("/token", (req, res) => {
  const token = req.get("x-auth-token");

  if (!token || !token.startsWith("Bearer ")) return res.json({ message: 'No token' });

  verify(
    token.split(" ")[1],
    jwtSecret,
    (err, decoded) => res.json({ message: err ? 'Invalid token' : decoded.user })
  );
});

// @route    POST /api/users/register
// @desc     Register new user
// @access   Public
router.post("/register", async (req, res) => {
  const { name, phone, password } = req.body;

  try {
    const userExisting = await Users.findOne({ phone });
    if (userExisting) return res.status(409).json({
      message: "This phone number is already registered. Please try logging in."
    });

    const
      salt = await genSalt(10),
      hashed = await hash(password, salt),
      user = new Users({
        name,
        phone,
        password: hashed
      }),
      savedUser = await user.save(),
      token = createToken(savedUser._doc._id.toString());

    return res.status(200).json({ message: "New user created", token });    
  } catch (error) {
    res.status(500).json({ message: "Error caught", error });
  }
});

// @route    POST /api/users/login
// @desc     Log in using phone and password
// @access   Public
router.post("/login", async (req, res) => {
  const { phone, password } = req.body;

  try {
    const user = await Users.findOne({ phone });
    if (!user) return res.status(404).json({
      message: "Phone number is not registered"
    });

    const isMatch = await compare(password, user.password);
    if(!isMatch) return res.status(401).json({
      message: "Incorrect password"
    });

    const token = createToken(user._doc._id.toString());

    res.json({ token });
  } catch (error) {
    res.status(500).send({ error: err.message, error });
  }
});

// @route    GET /api/users/data
// @desc     Get signed-in user via token
// @access   Private
router.get("/data", authMiddleware, async (req, res) => {
  const { idUser } = req;
  
  try {
    const user = await Users
      .findById(idUser)
      .select("-password")
      .populate("fields machines services");

    res.json({ user });
  } catch (error) {
    res.status(500).send({ message: error.message, error });
  }
});

// @route    GET /api/users/providers
// @desc     Get users who are providers
// @access   Private
router.get("/providers", async (req, res) => {
  try {
    const providers = await Users
      .find({ uType: "Provider" })
      .select("-password")
      .populate("fields machines services");

    res.json({ providers });
  } catch (error) {
    res.status(500).send({ message: error.message, error });
  }
});

// @route    POST /api/users/save
// @desc     Save user data
// @access   Private
router.post("/save", authMiddleware, async (req, res) => {
  const
    { idUser, body } = req,
    {
      _id,
      name,
      uType,
      adm1,
      adm2,
      adm3,
      address,
      lon,
      lat,
      dob,
      sex,
      fields,
      machines
    } = body;

  let newEntries = [];

  try {
    if (_id !== idUser) {

      return res
        .status(406)
        .json({
          message: "User ID doesn't match"
        });

    } else if (
      !name ||
      !uType ||
      !adm1 ||
      !adm2 ||
      !adm3 ||
      !address ||
      !lon ||
      !lat
    ) {

      return res
        .status(406)
        .json({
          message: "Please make sure the following required information have been provided:\nName, User Type, Address, Geolocation"
        });

    } else if (uType) {

      const userQueried = await Users.findById(idUser);

      userQueried.name = name;
      userQueried.uType = uType;
      userQueried.adm1 = adm1;
      userQueried.adm2 = adm2;
      userQueried.adm3 = adm3;
      userQueried.address = address;
      userQueried.lon = +lon;
      userQueried.lat = +lat;
      if(dob) userQueried.dob = +dob;
      if(sex) userQueried.sex = sex;

      if(uType === 'Farmer') {

        if(!fields.length) return res
          .status(406)
          .json({
            message: "Please enlist field data in the 'Fields' tab of the profile page"
          });

        if(fields.some(field => (
          !field.lon ||
          !field.lat ||
          !field.area
        ))) return res
          .status(406)
          .json({
            message: "Please make sure you have provided the following for all of the fields:\nGeolocation, Area"
          });

        const fieldsQueried = await Fields.find({ owner: idUser });

        for(const fieldQueried of fieldsQueried) {

          const oidFieldQueried = fieldQueried._doc._id.toString();
          if(fields.map(field => field._id || '').indexOf(oidFieldQueried) === -1) {
            await Fields.findByIdAndDelete(oidFieldQueried);
            const i = userQueried.fields.map(oid => oid.toString()).indexOf(oidFieldQueried);
            userQueried.fields.splice(i, 1);
          }

        }

        for (const field of fields) {
          if('_id' in field) {

            const fieldQueried = await Fields.findById(field._id);

            fieldQueried.address = field.address;
            fieldQueried.lon = +field.lon;
            fieldQueried.lat = +field.lat;
            fieldQueried.area = +field.area;

            await fieldQueried.save();

          } else {

            const
              newField = new Fields({
                address: field.address,
                owner: idUser,
                lon: +field.lon,
                lat: +field.lat,
                area: +field.area
              }),
              savedField = await newField.save();

            newEntries.push(savedField);
            userQueried.fields.push(savedField._doc._id.toString());

          }
        }

      } else if (uType === 'Provider') {

        if(!machines.length) return res
          .status(406)
          .json({
            message: "Please enlist machine information in the 'Details' section of your profile"
          });

        if(machines.some(machine => (
          !machine.name ||
          !machine.manufacturer
        ))) return res
          .status(406)
          .json({
            message: "Please make sure you have provided the following for all of the machines:\nType, Manufacturer"
          });

        const machinesQueried = await Machines.find({ owner: idUser });

        for(const machineQueried of machinesQueried) {

          const oidMachineQueried = machineQueried._doc._id.toString();
          if(machines.map(machine => machine._id || '').indexOf(oidMachineQueried) === -1) {

            await Machines.findByIdAndDelete(oidMachineQueried);
            const i = userQueried.machines.map(oid => oid.toString()).indexOf(oidMachineQueried);
            userQueried.machines.splice(i, 1);

          }

        }

        for (const machine of machines) {
          if('_id' in machine) {

            const machineQueried = await Machines.findById(machine._id);

            machineQueried.name = machine.name;
            machineQueried.description = machine.description;
            machineQueried.manufacturer = machine.manufacturer;

            await machineQueried.save();

          } else {

            const
              newMachine = new Machines({
                name: machine.name,
                description: machine.description,
                owner: idUser,
                manufacturer: machine.manufacturer
              }),
              savedMachine = await newMachine.save();

            newEntries.push(savedMachine);
            userQueried.machines.push(savedMachine._doc._id.toString());

          }
        }

      }

      const userSaved = await userQueried.save();
      await Users.populate(userSaved, { path: "fields machines" });

      return res.json({ user: userSaved });

    } else {

      return res.status(400).json({
        message: "Unknown error"
      });

    }

  } catch (error) {
    return res.status(500).send({ message: error.message, error });
  }
});

module.exports = router;
