const
  { Schema, model } = require("mongoose"),

  UserSchema = new Schema({
    name: { type: String, required: true },
    phone: { type: String, unique: true },
    password: { type: String, required: true },
    uType: { type: String, default: '' },
    picture: { type: String, default: null },
    adm1: { type: String, default: '' },
    adm2: { type: String, default: '' },
    adm3: { type: String, default: '' },
    address: { type: String, default: '' },
    lon: { type: Number, default: null },
    lat: { type: Number, default: null },
    dob: { type: Number, default: null },
    sex: { type: String },
    test: { type: Boolean, default: false },
    machines: [
      { type: Schema.Types.ObjectId, ref: "machines", required: true }
    ],
    fields: [
      { type: Schema.Types.ObjectId, ref: "fields", required: true }
    ],
    services: [
      { type: Schema.Types.ObjectId, ref: "services", required: true }
    ]
  });

module.exports = model("users", UserSchema);
