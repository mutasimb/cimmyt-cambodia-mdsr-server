const
  express = require("express"),
  authMiddleware = require("../middleware/auth.js"),

  Users = require("../models/Users.js"),
  Services = require("../models/Services.js"),

  router = express.Router();

router.post('/new', authMiddleware, async (req, res) => {
  const
    { idUser } = req,
    {
      provider,
      field,
      machine
    } = req.body;

  try {
    const
      service = new Services({
        client: idUser,
        provider,
        clientSeen: true,
        clientAgreed: true,
        field,
        machine
      }),

      savedService = await service.save(),

      userClient = await Users.findById(idUser).select("-password"),
      userProvider = await Users.findById(provider).select("-password");

    userClient.services.push(savedService._id);
    userProvider.services.push(savedService._id);

    const
      savedUserClient = await userClient.save(),
      savedUserProvider = await userProvider.save();

    await Users.populate(savedUserClient, { path: "fields machines services" });
    await Users.populate(savedUserProvider, { path: "fields machines services" });

    return res.json({
      service: savedService,
      client: savedUserClient,
      provider: savedUserProvider
    });

  } catch (error) {

    return res.status(500).send({
      message: error.message,
      error
    });

  }
});

router.get('/user', authMiddleware, async (req, res) => {
  const { idUser } = req;

  try {
    const
      user = await Users.findById(idUser).select("-password"),
      services = user.uType === "Farmer"
        ? await Services.find({ client: idUser }).populate("client provider field machine", "-password")
        : user.uType === "Provider"
        ? await Services.find({ provider: idUser }).populate("client provider field machine", "-password")
        : [];

    return res.json({ services });

  } catch (error) {

    return res.status(500).send({
      message: error.message,
      error
    });

  }
});

module.exports = router;
