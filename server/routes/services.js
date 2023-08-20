const
  express = require("express"),
  authMiddleware = require("../middleware/auth.js"),

  Users = require("../models/Users.js"),
  Services = require("../models/Services.js"),

  router = express.Router();

router.post('/new', authMiddleware, async (req, res) => {
  const
    { idUser, body } = req,
    {
      provider,
      field,
      machine,
      service: serviceType,
      dateStart
    } = body;

  try {
    const
      service = new Services({
        client: idUser,
        provider,
        clientSeen: true,
        clientAgreed: true,
        field,
        machine,
        service: serviceType,
        dateStart
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

router.post('/save', authMiddleware, async (req, res) => {
  const
    { idUser } = req,
    {
      _id,
      service,
      provider,
      client,
      field,
      machine,
      dateStart,
      dateEnd,
      status,
      cost,
      statusPayment
    } = req.body;

  try {
    const serviceItem = await Services.findById(_id);

    serviceItem.dateStart = dateStart;
    serviceItem.dateEnd = dateEnd;
    serviceItem.field = field;
    serviceItem.machine = machine;
    serviceItem.service = service;
    serviceItem.status = status === '' ? 'Pending' : status;
    serviceItem.cost = cost;
    serviceItem.statusPayment = statusPayment;

    const savedServiceItem = await serviceItem.save();
    await Services.populate(savedServiceItem, {
      path: "client provider field machine",
      select: "-password"
    });

    return res.json({ service: savedServiceItem });

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
