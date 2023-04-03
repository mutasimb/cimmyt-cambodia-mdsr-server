const
  { Schema, model } = require("mongoose"),

  ServiceSchema = new Schema({
    client: { type: Schema.Types.ObjectId, ref: "users", required: true },
    provider: { type: Schema.Types.ObjectId, ref: "users", required: true },
    dateStart: { type: Number, default: null },
    dateEnd: { type: Number, default: null },
    clientSeen: { type: Boolean, default: false },
    providerSeen: { type: Boolean, default: false },
    clientAgreed: { type: Boolean, default: false },
    providerAgreed: { type: Boolean, default: false },
    field: { type: Schema.Types.ObjectId, ref: "fields", required: true },
    machine: { type: Schema.Types.ObjectId, ref: "machines", required: true },
    service: { type: String, default: 'Seeding' },
    status: { type: String, default: '' },
    cost: { type: Number, default: 0 },
    statusPayment: { type: String, default: "Unpaid" }
  });

module.exports = model("services", ServiceSchema);
