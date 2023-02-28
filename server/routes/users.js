const
  express = require("express"),
  { genSalt, hash, compare } = require("bcryptjs"),

  authMiddleware = require("../middleware/auth.js"),
  createToken = require("../utils/token.js"),

  Users = require("../models/Users.js"),
  Fields = require("../models/Fields.js"),
  Machines = require("../models/Machines.js"),
  Services = require("../models/Services.js"),

  router = express.Router();


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
// @desc     Get user signed-in user via token
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
router.get("/providers", authMiddleware, async (req, res) => {
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
      !lat ||
      !dob ||
      !sex
    ) {

      return res
        .status(406)
        .json({
          message: "Please make sure the following required information have been provided:\nName, User Type, Address, Geolocation, Date of Birth, Sex"
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
      userQueried.dob = +dob;
      userQueried.sex = sex;

      if(uType === 'Farmer') {

        if(!fields.length) return res
          .status(406)
          .json({
            message: "Please enlist at least one field in the 'Details' section of your profile"
          });

        if(fields.some(field => (
          !field.name ||
          !field.lon ||
          !field.lat ||
          !field.area
        ))) return res
          .status(406)
          .json({
            message: "Please make sure you have provided the following for all of the fields:\nLabel, Geolocation, Area"
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

            fieldQueried.name = field.name;
            fieldQueried.description = field.description;
            fieldQueried.lon = +field.lon;
            fieldQueried.lat = +field.lat;
            fieldQueried.area = +field.area;

            await fieldQueried.save();

          } else {

            const
              newField = new Fields({
                name: field.name,
                description: field.description,
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
            message: "Please enlist at least one machine in the 'Details' section of your profile"
          });

        if(machines.some(machine => (
          !machine.name ||
          !machine.manufacturer
        ))) return res
          .status(406)
          .json({
            message: "Please make sure you have provided the following for all of the machines:\nLabel, Manufacturer"
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
