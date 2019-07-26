//jshint esversion: 8

require("dotenv").config();
var express = require("express");
var parser = require("body-parser");
var request = require("request");
var io = require("socket.io");
var sql = require("mssql");
var crypto = require("crypto");
var bcrypt = require("bcrypt");
var jwt = require("jsonwebtoken");
var fs = require("fs");
var sharp = require("sharp");
var xml2js = require("xml2js");
var http = require("http");
var expressSession = require("express-session");
var session = require("socket.io-express-session");
var sessionFileStore = require("session-file-store");
var Geonames = require("geonames.js");

var SessionStore = sessionFileStore(expressSession);
var store = new SessionStore({
	path: __dirname + "/temp/sessions"
});

var expSession = expressSession({
	store: store,
	secret: process.env.SESSION_SECRET,
	resave: true,
	saveUninitialized: true
});

var app = express();
app.use(expSession);
app.use(parser.urlencoded({
	extended: true
}));
app.use(parser.json({
	limit: "50mb"
}));

var server = http.createServer(app);
var socket = io.listen(server);

socket.use(function(conn, next) {
	conn.request.originalUrl = conn.request.url;
	expSession(conn.request, conn.request.res, next);
}, {
	autoSave: true
});

var geonames = new Geonames({
	username: process.env.GEONAMES_USERNAME,
	lan: "en",
	encoding: "JSON"
});

var imageFolderUrl = "https://mgas006-mgas-ws.webware.om:1995/images/";


// Encryption and decryption
var algorithm = process.env.ENCRYPT_ALGO;
var imgAlgo = process.env.ENCRYPT_IMG_ALGO;
var key = process.env.ENCRYPT_KEY;

function encrypt(plaintext) {
	var salt = crypto.randomBytes(16).toString("hex");
	var derived = crypto.scryptSync(key, salt, 24);
	var iv = crypto.randomBytes(16).toString("hex");
	var cipher = crypto.createCipheriv(algorithm, derived, iv);
	var ciphertext = cipher.update(plaintext, "utf8", "hex");
	ciphertext += cipher.final("hex");
	var tag = cipher.getAuthTag().toString("hex");
	ciphertext = salt + iv + ciphertext + tag;
	return ciphertext;
}

function decrypt(ciphertext) {
	var salt = ciphertext.slice(0, 32);
	var iv = ciphertext.slice(32, 64);
	var tag = ciphertext.slice(-32);
	var text = ciphertext.slice(64, -32);
	var derived = crypto.scryptSync(key, salt, 24);
	var decipher = crypto.createDecipheriv(algorithm, derived, iv);
	var authTag = Buffer.from(tag, "hex");
	decipher.setAuthTag(authTag);
	var plaintext = decipher.update(text, "hex", "utf8");
	plaintext += decipher.final("utf8");
	return plaintext;
}

function encryptImage(image) {
	var salt = crypto.randomBytes(8).toString("hex");
	var derived = crypto.scryptSync(key, salt, 24);
	var iv = crypto.randomBytes(8).toString("hex");
	var cipher = crypto.createCipheriv(imgAlgo, derived, iv);
	var img = cipher.update(image);
	img = Buffer.concat([img, cipher.final()]);
	var additions = salt + iv;
	var addBuff = Buffer.from(additions, "hex");
	var encrypted = Buffer.concat([img, addBuff]);
	return encrypted;
}

function decryptImage(encrypted) {
	var data = encrypted.slice(0, -16);
	var addBuff = encrypted.slice(-16);
	var additions = addBuff.toString("hex");
	var salt = additions.slice(0, 16);
	var iv = additions.slice(-16);
	var derived = crypto.scryptSync(key, salt, 24);
	var decipher = crypto.createDecipheriv(imgAlgo, derived, iv);
	var img = decipher.update(data);
	img = Buffer.concat([img, decipher.final()]);
	return img;
}


// Database connection
var dbConfig = {
	user: process.env.DB_USER,
	password: process.env.DB_PASSWORD,
	server: process.env.DB_SERVER,
	database: process.env.DB,
	parseJSON: true
};

async function dbConnect() {
	try {
		await sql.connect(dbConfig);
	} catch (err) {
		var msg = "Error connecting to the database: " + err;
		console.log(msg + "\n");
	}
}

dbConnect();


// JWT authorization middlewear
function authorizeGeneral(req, res, next) {
	var header = req.headers.authorization;

	if (header) {
		if (header.startsWith("Bearer ")) {
			var token = header.split(' ')[1];
			jwt.verify(token, process.env.JWT_SECRET, function(err, payload) {
				if (err) {
					res.status(403).json({
						error: "Invalid or unauthorized token"
					});
					console.log(res.statusCode + " - " + res.statusMessage + "\n");
					console.log("Error: Invalid or unauthorized token\n");
				} else {
					next();
				}
			});
		} else {
			res.status(403).json({
				error: "No Bearer token found"
			});
			console.log(res.statusCode + " - " + res.statusMessage + "\n");
			console.log("Error: No Bearer token found\n");
		}
	} else {
		res.status(403).json({
			error: "No authorization header found"
		});
		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error: No authorization header found\n");
	}
}

function authorizeConsumer(req, res, next) {
	var header = req.headers.authorization;

	if (header) {
		if (header.startsWith("Bearer ")) {
			var token = header.split(' ')[1];
			jwt.verify(token, process.env.JWT_SECRET, function(err, payload) {
				if (err) {
					res.status(403).json({
						error: "Invalid or unauthorized token"
					});
					console.log(res.statusCode + " - " + res.statusMessage + "\n");
					console.log("Error: Invalid or unauthorized token\n");
				} else {
					if (payload.id === req.params.user && payload.userType === "consumer") {
						next();
					} else {
						res.status(403).json({
							error: "Unauthorized user"
						});
						console.log(res.statusCode + " - " + res.statusMessage + "\n");
						console.log("Error: Unauthorized user\n");
					}
				}
			});
		} else {
			res.status(403).json({
				error: "No Bearer token found"
			});
			console.log(res.statusCode + " - " + res.statusMessage + "\n");
			console.log("Error: No Bearer token found\n");
		}
	} else {
		res.status(403).json({
			error: "No authorization header found"
		});
		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error: No authorization header found\n");
	}
}

function authorizeDriver(req, res, next) {
	var header = req.headers.authorization;

	if (header) {
		if (header.startsWith("Bearer ")) {
			var token = header.split(' ')[1];
			jwt.verify(token, process.env.JWT_SECRET, function(err, payload) {
				if (err) {
					res.status(403).json({
						error: "Invalid or unauthorized token"
					});
					console.log(res.statusCode + " - " + res.statusMessage + "\n");
					console.log("Error: Invalid or unauthorized token\n");
				} else {
					if (payload.id === req.params.user && payload.userType === "driver") {
						next();
					} else {
						res.status(403).json({
							error: "Unauthorized user"
						});
						console.log(res.statusCode + " - " + res.statusMessage + "\n");
						console.log("Error: Unauthorized user\n");
					}
				}
			});
		} else {
			res.status(403).json({
				error: "No Bearer token found"
			});
			console.log(res.statusCode + " - " + res.statusMessage + "\n");
			console.log("Error: No Bearer token found\n");
		}
	} else {
		res.status(403).json({
			error: "No authorization header found"
		});
		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error: No authorization header found\n");
	}
}

function authorizeAdmin(req, res, next) {
	var header = req.headers.authorization;

	if (header) {
		if (header.startsWith("Bearer ")) {
			var token = header.split(' ')[1];
			jwt.verify(token, process.env.JWT_SECRET, function(err, payload) {
				if (err) {
					res.status(403).json({
						error: "Invalid or unauthorized token"
					});
					console.log(res.statusCode + " - " + res.statusMessage + "\n");
					console.log("Error: Invalid or unauthorized token\n");
				} else {
					if (payload.userType === "admin") {
						next();
					} else {
						res.status(403).json({
							error: "Not an admin user"
						});
						console.log(res.statusCode + " - " + res.statusMessage + "\n");
						console.log("Error: Not an admin user\n");
					}
				}
			});
		} else {
			res.status(403).json({
				error: "No Bearer token found"
			});
			console.log(res.statusCode + " - " + res.statusMessage + "\n");
			console.log("Error: No Bearer token found\n");
		}
	} else {
		res.status(403).json({
			error: "No authorization header found"
		});
		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error: No authorization header found\n");
	}
}

// Socket connection and real-time events
socket.on("connection", function(conn) {
	console.log("Client is connected\n");

	conn.on("userConnected", function(id) {
		conn.join(id);
	});

	conn.on("consumerRegisterOtp", async function(mobile) {
		console.log("Client emit - register send OTP\n");

		var req = new sql.Request();
		req.input("mobileNo", sql.Int, mobile);

		var q = "select * from users where mobileNo=@mobileNo";

		var msg;
		var statusCode;
		var statusMessage;
		var error;

		try {
			var result = await req.query(q);

			if (result.recordset.length !== 0) {
				msg = "This user is already registered";
				statusCode = 409;
				statusMessage = "Conflict";

				error = {
					msg: msg,
					statusCode: statusCode,
					statusMessage: statusMessage
				};

				conn.emit("consumerRegistrationError", error);
				console.log(statusCode + " - " + statusMessage + "\n");
				console.log(msg + "\n");
			} else {
				var otp = Math.floor(Math.random() * (9999 - 2)) + 1;
				otp = otp.toString().padStart(4, '0');

				var res = await sendCode(otp, mobile, true);
				if (res.err) {
					msg = "Error: Could not send OTP: " + res.err;
					statusCode = 500;
					statusMessage = "Internal Server Error";

					error = {
						msg: msg,
						statusCode: statusCode,
						statusMessage: statusMessage
					};

					conn.emit("consumerRegistrationError", error);
					console.log(statusCode + " - " + statusMessage + "\n");
					console.log(msg + "\n");
				} else {
					conn.handshake.otp = otp;
					conn.handshake.sendTime = res.sendTime;
					conn.emit("otpSent");
					console.log("OTP: " + otp + "\n");
				}
			}
		} catch (err) {
			msg = "Error while verifying if user already exists: " + err;
			statusCode = 400;
			statusMessage = "Bad Request";

			error = {
				msg: msg,
				statusCode: statusCode,
				statusMessage: statusMessage
			};

			conn.emit("consumerRegistrationError", error);
			console.log(statusCode + " - " + statusMessage + "\n");
			console.log(msg + "\n");
		}
	});

	conn.on("verifyOtp", function(otp) {
		console.log("Client emit - verify OTP\n");

		var msg;
		var statusCode;
		var statusMessage;

		/*		if ((Date.now() - conn.handshake.sendTime) / 1000 > 60) {
					msg = "OTP code is no longer valid";
					statusCode = 403;
					statusMessage = "Forbidden";
				} else*/
		if (otp !== conn.handshake.otp) {
			msg = "OTP code is incorrect";
			// arabicMsg = "الرمز المدخل غير صحيح";
			arabicMsg = otp + " " + conn.handshake.otp;
			statusCode = 403;
			statusMessage = "Forbidden";
		} else {
			msg = "Verified";
			// arabicMsg = "تم التحقيق";
			arabicMsg = otp + " " + conn.handshake.otp;
			statusCode = 200;
			statusMessage = "OK";
		}

		var res = {
			msg: msg,
			arabicMsg: arabicMsg,
			statusCode: statusCode,
			statusMessage: statusMessage
		};

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(res.msg + "\n");

		conn.emit("otpVerificationDone", res);
	});

	conn.on("addressSpecified", async function(address) {
		console.log("Client emit - geocode request\n");

		try {
			var tokens = address.split(", ");
			var country = await geocode(tokens[0]);
			country = JSON.parse(country);
			var bounds = country.results[0].geometry.bounds;

			var governorate = await geocode(tokens[1], bounds);
			governorate = JSON.parse(governorate);
			bounds = governorate.results[0].geometry.bounds;

			var province = await geocode(tokens[2], bounds);
			province = JSON.parse(province);
			bounds = province.results[0].geometry.bounds;

			var city = await geocode(tokens[3], bounds);
			city = JSON.parse(city);
			bounds = city.results[0].geometry.bounds;

			var street = await geocode(tokens[4], bounds);
			street = JSON.parse(street);
			bounds = street.results[0].geometry.bounds;

			var way = await geocode(tokens[5], bounds);
			way = JSON.parse(way);

			var location;
			if (tokens.length === 7) {
				bounds = way.results[0].geometry.bounds;

				var loc = await geocode(tokens[6], bounds);
				loc = JSON.parse(loc);

				location = loc.results[0].geometry.location;
			} else {
				location = way.results[0].geometry.location;
			}

			conn.emit("locationFound", location);
		} catch (err) {
			var msg = "Error searching for location: " + err;
			var statusCode = 400;
			var statusMessage = "Bad Request";

			var error = {
				msg: msg,
				statusCode: statusCode,
				statusMessage: statusMessage
			};

			conn.emit("addressSearchError", error);
			console.log(statusCode + " - " + statusMessage + "\n");
			console.log(err);
			console.log();
		}
	});

	conn.on("consumerRegister", async function(detailsJson) {
		console.log("Client emit - Consumer registration\n");

		var details = JSON.parse(detailsJson);

		var id = crypto.createHash("md5").update(details.idNo.toString()).digest("hex");

		var locationId = details.latitude.toString() + details.longitude.toString() + id;
		locationId = crypto.createHash("md5").update(locationId).digest("hex");

		var location = details.addressLine1.split(", ");

		var req = new sql.Request();
		req.input("locId", sql.Char(32), locationId);
		req.input("lng", sql.NVarChar(140), encrypt(details.longitude.toString()));
		req.input("lat", sql.NVarChar(140), encrypt(details.latitude.toString()));
		req.input("address", sql.NVarChar(500), encrypt(details.addressLine1));
		req.input("city", sql.NVarChar(200), encrypt(location[3]));
		req.input("province", sql.NVarChar(200), encrypt(location[2]));
		req.input("governorate", sql.NVarChar(200), encrypt(location[1]));
		req.input("country", sql.NVarChar(200), encrypt(location[0]));
		req.input("id", sql.Char(32), id);
		req.input("mobile", sql.Int, details.mobileNo);
		req.input("password", sql.Char(60), bcrypt.hashSync(details.password, 10));
		req.input("email", sql.NVarChar(300), encrypt(details.email));
		req.input("idNo", sql.NVarChar(120), encrypt(details.idNo.toString()));
		req.input("fName", sql.NVarChar(140), encrypt(details.fname));
		req.input("lName", sql.NVarChar(140), encrypt(details.lname));
		req.input("userType", sql.NVarChar(8), "consumer");
		req.input("mainLocId", sql.Char(32), locationId);
		req.input("mainLocName", sql.NVarChar(40), details.locName);

		var q = "insert into locations(id, longitude, latitude, addressLine1, city, province, " +
			"governorate, country) values(@locId, @lng, @lat, @address, @city, @province, " +
			"@governorate, @country);" +
			"insert into users(id, mobileNo, password, email, idNo, fName, lName, userType)" +
			"values(@id, @mobile, @password, @email, @idNo, @fName, @lName, @userType);" +
			"insert into consumers(userId, mainLocationId, mainLocationName) values(@id, " +
			"@mainLocId, @mainLocName);" +
			"insert into consumerLocations values(@id, @locId, @mainLocName)";

		try {
			await req.query(q);

			var payload = {
				id: id,
				userType: "consumer"
			};

			var options = {
				expiresIn: "7d"
			};

			var token = jwt.sign(payload, process.env.JWT_SECRET, options);

			var user = {
				id: id,
				mobileNo: details.mobileNo,
				email: details.email,
				idNo: details.idNo,
				fName: details.fname,
				lName: details.lname,
				displayPicThumb: null,
				displayPicUrl: null,
				userType: "consumer"
			};

			var consumer = {
				userId: id,
				gender: null,
				dateOfBirth: null,
				age: null,
				mainLocationId: locationId,
				mainLocationName: details.locName
			};

			var mainLocation = {
				id: locationId,
				longitude: details.longitude,
				latitude: details.latitude,
				addressLine1: details.addressLine1,
				addressLine2: null,
				city: location[3],
				province: location[2],
				governorate: location[1],
				country: location[0],
				locationName: details.locName
			};

			var userData = {
				token: token,
				user: user,
				consumer: consumer,
				mainLocation: mainLocation
			};

			conn.emit("consumerRegistrationSuccess", userData);
			console.log("200 - Ok\n");
			console.log(token + "\n");
		} catch (err) {
			var msg = "Error while creating user: " + err;
			var statusCode = 400;
			var statusMessage = "Bad Request";

			var error = {
				msg: msg,
				statusCode: statusCode,
				statusMessage: statusMessage
			};

			conn.emit("consumerRegistrationError", error);
			console.log(statusCode + " - " + statusMessage + "\n");
			console.log(msg + "\n");
		}
	});

	conn.on("driverRegisterOtp", async function(mobile) {
		console.log("Client emit - Driver registration OTP\n");

		var req = new sql.Request();
		req.input("mobile", sql.Int, mobile);

		var q = "select * from users where mobileNo=@mobile";

		var msg;
		var statusCode;
		var statusMessage;
		var error;

		try {
			var res = await req.query(q);

			if (res.recordset.length !== 0) {
				msg = "This user is already registered";
				statusCode = 409;
				statusMessage = "Conflict";

				error = {
					msg: msg,
					statusCode: statusCode,
					statusMessage: statusMessage
				};

				conn.emit("driverRegistrationError", error);
				console.log(statusCode + " - " + statusMessage + "\n");
				console.log(msg + "\n");
			} else {
				var otp = Math.floor(Math.random() * (9999 - 2)) + 1;
				otp = otp.toString().padStart(4, '0');

				var result = await sendCode(otp, mobile, true);
				if (result.err) {
					msg = "Error: Could not send OTP: " + result.err;
					statusCode = 500;
					statusMessage = "Internal Server Error";

					error = {
						msg: msg,
						statusCode: statusCode,
						statusMessage: statusMessage
					};

					conn.emit("driverRegistrationError", error);
					console.log(statusCode + " - " + statusMessage + "\n");
					console.log(msg + "\n");
				} else {
					conn.handshake.otp = otp;
					conn.handshake.sendTime = result.sendTime;
					conn.emit("otpSent");
					console.log("OTP: " + otp + "\n");
				}
			}
		} catch (err) {
			msg = "Error while verifying if user already exists: " + err;
			statusCode = 400;
			statusMessage = "Bad Request";

			error = {
				msg: msg,
				statusCode: statusCode,
				statusMessage: statusMessage
			};

			conn.emit("driverRegistrationError", error);
			console.log(statusCode + " - " + statusMessage + "\n");
			console.log(msg + "\n");
		}
	});

	conn.on("driverRegister", async function(driverJson) {
		console.log("Client emit - Driver registration\n");

		var driver = JSON.parse(driverJson);

		var mobile = driver.mobileNo;
		var pass = driver.password;
		var email = driver.email;
		var idNo = driver.idNo;
		var fname = driver.fname;
		var lname = driver.lname;

		var plateCode = driver.plateCode;
		var plateNumber = driver.plateNumber;
		var bankName = driver.bankName;
		var bankBranch = driver.bankBranch;
		var bankAccountName = driver.bankAccountName;
		var bankAccountNo = driver.bankAccountNo;
		var addressLine1 = driver.addressLine1;
		var addressLine2 = driver.addressLine2;
		var city = driver.city;
		var province = driver.province;
		var governorate = driver.governorate;
		var country = driver.country;
		var gasTransCert = driver.gasTransCert;
		var civilCerts = driver.civilCerts;
		var applicationCreditForm = driver.applicationCreditForm;
		var cr = driver.cr;
		var occiCert = driver.occiCert;
		var sponsorId = driver.sponsorId;
		var guaranteeCheque = driver.guaranteeCheque;
		var signDoc = driver.signDoc;
		var civilDefianceCert = driver.civilDefianceCert;
		var lpgSaleApproval = driver.lpgSaleApproval;

		var id = crypto.createHash("md5").update(idNo.toString()).digest("hex");

		var gasTransCertImg = fs.readFileSync(gasTransCert);
		var civilCertsImg = fs.readFileSync(civilCerts);
		var applicationCreditFormImg = fs.readFileSync(applicationCreditForm);
		var crImg = fs.readFileSync(cr);
		var occiCertImg = fs.readFileSync(occiCert);
		var sponsorIdImg = fs.readFileSync(sponsorId);
		var guaranteeChequeImg = fs.readFileSync(guaranteeCheque);
		var signDocImg = fs.readFileSync(signDoc);
		var civilDefianceCertImg = fs.readFileSync(civilDefianceCert);
		var lpgSaleApprovalImg = fs.readFileSync(lpgSaleApproval);

		var gasTransCertImgName = "gasTransCert." +
			gasTransCert.split('.')[gasTransCert.split('.').length - 1];
		var civilCertsImgName = "civilCerts." +
			civilCerts.split('.')[civilCerts.split('.').length - 1];
		var applicationCreditFormImgName = "applicationCreditForm." +
			applicationCreditForm.split('.')[applicationCreditForm.split('.').length - 1];
		var crImgName = "cr." + cr.split('.')[cr.split('.').length - 1];
		var occiCertImgName = "occiCert." + occiCert.split('.')[occiCert.split('.').length - 1];
		var sponsorIdImgName = "sponsorId." + sponsorId.split('.')[sponsorId.split('.').length - 1];
		var guaranteeChequeImgName = "guaranteeCheque." +
			guaranteeCheque.split('.')[guaranteeCheque.split('.').length - 1];
		var signDocImgName = "signDoc." + signDoc.split('.')[signDoc.split('.').length - 1];
		var civilDefianceCertImgName = "civilDefianceCert." +
			civilDefianceCert.split('.')[civilDefianceCert.split('.').length - 1];
		var lpgSaleApprovalImgName = "lpgSaleApproval." +
			lpgSaleApproval.split('.')[lpgSaleApproval.split('.').length - 1];

		var dir = __dirname + "/Images/Users/" + id + "/";

		if (!fs.existsSync(dir)) {
			fs.mkdirSync(dir);
		}

		fs.writeFileSync(dir + gasTransCertImgName, gasTransCertImg);
		fs.writeFileSync(dir + civilCertsImgName, civilCertsImg);
		fs.writeFileSync(dir + applicationCreditFormImgName, applicationCreditFormImg);
		fs.writeFileSync(dir + crImgName, crImg);
		fs.writeFileSync(dir + occiCertImgName, occiCertImg);
		fs.writeFileSync(dir + sponsorIdImgName, sponsorIdImg);
		fs.writeFileSync(dir + guaranteeChequeImgName, guaranteeChequeImg);
		fs.writeFileSync(dir + signDocImgName, signDocImg);
		fs.writeFileSync(dir + civilDefianceCertImgName, civilDefianceCertImg);
		fs.writeFileSync(dir + lpgSaleApprovalImgName, lpgSaleApprovalImg);

		var baseUrl = imageFolderUrl + "/Users/" + id + "/";

		var request = new sql.Request();
		request.input("id", sql.Char(32), id);
		request.input("mobile", sql.Int, mobile);
		request.input("pass", sql.Char(60), bcrypt.hashSync(pass, 10));
		request.input("email", sql.NVarChar(300), encrypt(email));
		request.input("idNo", sql.NVarChar(120), encrypt(idNo.toString()));
		request.input("fname", sql.NVarChar(140), encrypt(fname));
		request.input("lname", sql.NVarChar(140), encrypt(lname));
		request.input("userType", sql.NVarChar(8), "driver");
		request.input("plateCode", sql.NVarChar(108), encrypt(plateCode));
		request.input("plateNumber", sql.NVarChar(116), encrypt(plateNumber.toString()));
		request.input("bankName", sql.NVarChar(160), encrypt(bankName));
		request.input("bankBranch", sql.NVarChar(140), encrypt(bankBranch));
		request.input("bankAccountName", sql.NVarChar(200), encrypt(bankAccountName));
		request.input("bankAccountNo", sql.NVarChar(140), encrypt(bankAccountNo.toString()));
		request.input("addressLine1", sql.NVarChar(500), encrypt(addressLine1));
		request.input("city", sql.NVarChar(200), encrypt(city));
		request.input("province", sql.NVarChar(200), encrypt(province));
		request.input("governorate", sql.NVarChar(200), encrypt(governorate));
		request.input("country", sql.NVarChar(200), encrypt(country));
		request.input("gasTransCert", sql.NVarChar(500), encrypt(baseUrl + gasTransCertImgName));
		request.input("civilCerts", sql.NVarChar(500), encrypt(baseUrl + civilCertsImgName));
		request.input("applicationCreditForm", sql.NVarChar(500),
			encrypt(baseUrl + applicationCreditFormImgName));
		request.input("cr", sql.NVarChar(500), encrypt(baseUrl + crImgName));
		request.input("occiCert", sql.NVarChar(500), encrypt(baseUrl + occiCertImgName));
		request.input("sponsorId", sql.NVarChar(500), encrypt(baseUrl + sponsorIdImgName));
		request.input("guaranteeCheque", sql.NVarChar(500), encrypt(baseUrl + guaranteeChequeImgName));
		request.input("signDoc", sql.NVarChar(500), encrypt(baseUrl + signDocImgName));
		request.input("civilDefianceCert", sql.NVarChar(500), encrypt(baseUrl + civilDefianceCertImgName));
		request.input("lpgSaleApproval", sql.NVarChar(500), encrypt(baseUrl + lpgSaleApprovalImgName));

		if (addressLine2) {
			request.input("addressLine2", sql.NVarChar(500), encrypt(addressLine2));
		} else {
			request.input("addressLine2", sql.NVarChar(500), addressLine2);
		}

		var q = "insert into users(id, mobileNo, password, email, idNo, fName, lName, userType)" +
			"values(@id, @mobile, @pass, @email, @idNo, @fName, @lName, @userType);" +
			"insert into drivers values(@id, @plateCode, @plateNumber, @bankName, @bankBranch, " +
			"@bankAccountName, @bankAccountNo, @addressLine1, @addressLine2, @city, @province, " +
			"@governorate, @country, @gasTransCert, @civilCerts, @applicationCreditForm, " +
			"@cr, @occiCert, @sponsorId, @guaranteeCheque, @signDoc, @civilDefianceCert, @lpgSaleApproval)";

		try {
			await request.query(q);

			var res = {
				msg: "Driver registered successfully",
				statusCode: 200,
				statusMessage: "OK"
			};

			conn.emit("driverRegistrationSuccess", res);
			console.log("200 - Ok\n");
			console.log("Driver registered successfully\n");
		} catch (err) {
			var msg = "Error while creating user: " + err;
			var statusCode = 400;
			var statusMessage = "Bad Request";

			var error = {
				msg: msg,
				statusCode: statusCode,
				statusMessage: statusMessage
			};

			conn.emit("driverRegistrationError", error);
			console.log(statusCode + " - " + statusMessage + "\n");
			console.log(msg + "\n");
		}
	});

	conn.on("login", async function(mobile, pass) {
		console.log("Client emit - login\n");

		var error;
		try {
			var req = new sql.Request();
			req.input("mobile", sql.Int, mobile);

			var q = "select * from users where mobileNo=@mobile";

			var results = await req.query(q);

			if (results.recordset.length === 0) {
				error = {
					msg: "This mobile number is not registered",
					arabicMsg: "رقم الجوال هذا غير مسجل",
					statusCode: 401,
					statusMessage: "Unauthorized"
				};

				conn.emit("loginError", error);
				console.log(error.statusCode + " - " + error.statusMessage + "\n");
				console.log(error.msg + "\n");
			} else {
				var user = results.recordset[0];

				if (bcrypt.compareSync(pass, user.password)) {
					var otp = Math.floor(Math.random() * (9999 - 2)) + 1;
					otp = otp.toString().padStart(4, '0');

					//////////////////////////////////////////////////////////////////////
					//////////////////////////////////////////////////////////////////////
					//////////////////////////////////////////////////////////////////////
					//////////////////////////////////////////////////////////////////////
					otp = "1234";
					//////////////////////////////////////////////////////////////////////
					//////////////////////////////////////////////////////////////////////
					//////////////////////////////////////////////////////////////////////
					//////////////////////////////////////////////////////////////////////

					if (user.userType === "driver") {
						await sendCode(otp, 95746197, true);
					}

					var res = await sendCode(otp, mobile, true);
					if (res.err) {
						error = {
							msg: "Error: Could not send OTP: " + res.err,
							statusCode: 500,
							statusMessage: "Internal Server Error"
						};

						console.log(res.err);
						console.log();

						conn.emit("loginError", error);
						console.log(error.statusCode + " - " + error.statusMessage + "\n");
						console.log(error.msg + "\n");
					} else {
						conn.handshake.otp = otp;
						conn.handshake.sendTime = res.sendTime;
						conn.handshake.user = user;
						conn.emit("otpSent");
						console.log("OTP: " + otp + "\n");
					}
				} else {
					error = {
						msg: "Incorrect password",
						statusCode: 401,
						statusMessage: "Unauthorized"
					};

					conn.emit("loginError", error);
					console.log(error.statusCode + " - " + error.statusMessage + "\n");
					console.log(error.msg + "\n");
				}
			}
		} catch (err) {
			error = {
				msg: "Error checking if user exists: " + err,
				statusCode: 400,
				statusMessage: "Bad Request"
			};

			conn.emit("loginError", error);
			console.log(error.statusCode + " - " + error.statusMessage + "\n");
			console.log(error.msg + "\n");
		}
	});

	conn.on("loginUserInfo", async function() {
		console.log("Client emit - Login user info\n");

		var user = conn.handshake.user;
		delete user.password;
		user.email = decrypt(user.email);
		user.idNo = parseInt(user.idNo);
		user.fName = decrypt(user.fName);
		user.lName = decrypt(user.lName);
		if (user.displayPicUrl && user.displayPicThumb) {
			user.displayPicThumb = Array.prototype.slice.call(decryptImage(user.displayPicThumb), 0);
			user.displayPicUrl = decrypt(user.displayPicUrl);
		}

		var payload = {
			id: user.id,
			userType: user.userType
		};

		var options = {
			expiresIn: "7d"
		};

		var token = jwt.sign(payload, process.env.JWT_SECRET, options);

		var req = new sql.Request();
		req.input("id", sql.Char(32), user.id);
		try {
			var getOrders;
			var getOrderServices = "select * from orderServices where orderId=@order";
			var getOrderFeedbacks = "select * from feedbacks where orderId=@order";
			var orders;
			var orderServices;
			var orderFeedbacks;
			var feedbacks;
			var data;
			if (user.userType === "consumer") {
				var getConsumer = "select * from consumers where userId=@id";
				var getBankCards = "select * from bankCards where owner=@id";
				var getLocations = "select l.*, cl.locationName " +
					"from locations as l, consumerLocations as cl, consumers as c " +
					"where cl.consumerId=c.userId and cl.locationId=l.id and cl.consumerId=@id";
				getOrders = "select * from orders where consumerId=@id";

				var consumer = await req.query(getConsumer);
				consumer = consumer.recordset[0];

				var cards = await req.query(getBankCards);
				cards = cards.recordset;

				var locations = await req.query(getLocations);
				locations = locations.recordset;

				orders = await req.query(getOrders);
				orders = orders.recordset;

				if (consumer.gender) {
					consumer.gender = decrypt(consumer.gender);
				}
				if (consumer.dateOfBirth && consumer.age) {
					consumer.dateOfBirth = new Date(decrypt(consumer.dateOfBirth));
					consumer.age = parseInt(decrypt(consumer.age));
				}

				for (var c of cards) {
					c.cardNo = decrypt(c.cardNo);
					c.expDateMonth = parseInt(decrypt(c.expDateMonth));
					c.expDateYear = parseInt(decrypt(c.expDateYear));
					c.cvv = parseInt(decrypt(c.cvv));
				}

				for (var l of locations) {
					l.longitude = parseFloat(decrypt(l.longitude));
					l.latitude = parseFloat(decrypt(l.latitude));
					l.addressLine1 = decrypt(l.addressLine1);
					l.city = decrypt(l.city);
					l.province = decrypt(l.province);
					l.governorate = decrypt(l.governorate);
					l.country = decrypt(l.country);

					if (l.addressLine2) {
						l.addressLine2 = decrypt(l.addressLine2);
					}
				}

				for (var o of orders) {
					o.orderDate = new Date(decrypt(o.orderDate));
					o.totalCost = parseFloat(decrypt(o.totalCost));

					req.input("order", sql.Char(32), o.id);

					orderServices = await req.query(getOrderServices);
					orderServices = orderServices.recordset;

					orderFeedbacks = await req.query(getOrderFeedbacks);
					orderFeedbacks = orderFeedbacks.recordset;

					for (var s of orderServices) {
						s.quantity = parseInt(decrypt(s.quantity));
					}

					for (var ofs of orderFeedbacks) {
						ofs.message = decrypt(ofs.message);
					}

					o.services = orderServices;
					o.feedbacks = orderFeedbacks;

					delete o.orderCode;
				}

				data = {
					token: token,
					user: user,
					consumer: consumer,
					cards: cards,
					locations: locations,
					orders: orders
				};

				conn.emit("loginSuccess", data);

				console.log("200 - Ok\n");
				console.log(data);
				console.log();
			} else { // if driver
				var getDriver = "select * from drivers where userId=@id";
				getOrders = "select * from orders where driverId=@id";
				var getIssues = "select * from deliveryIssues where driverId=@id";
				var getOrderLocations = "select * from locations where id in " +
					"(select locationId from orders where driverId=@id)";

				var driver = await req.query(getDriver);
				driver = driver.recordset[0];

				orders = await req.query(getOrders);
				orders = orders.recordset;

				var issues = await req.query(getIssues);
				issues = issues.recordset;

				var orderLocations = await req.query(getOrderLocations);
				orderLocations = orderLocations.recordset;

				driver.gasTransCert = decrypt(driver.gasTransCert);
				driver.civilCerts = decrypt(driver.civilCerts);
				driver.applicationCreditForm = decrypt(driver.applicationCreditForm);
				driver.cr = decrypt(driver.cr);
				driver.occiCert = decrypt(driver.occiCert);
				driver.sponsorId = decrypt(driver.sponsorId);
				driver.guaranteeCheque = decrypt(driver.guaranteeCheque);
				driver.civilDefianceCert = decrypt(driver.civilDefianceCert);
				driver.signDoc = decrypt(driver.signDoc);
				driver.lpgSaleApproval = decrypt(driver.lpgSaleApproval);
				driver.plateCode = decrypt(driver.plateCode);
				driver.plateNumber = parseInt(decrypt(driver.plateNumber));
				driver.bankName = decrypt(driver.bankName);
				driver.bankBranch = decrypt(driver.bankBranch);
				driver.bankAccountName = decrypt(driver.bankAccountName);
				driver.bankAccountNo = decrypt(driver.bankAccountNo);
				driver.addressLine1 = decrypt(driver.addressLine1);
				driver.city = decrypt(driver.city);
				driver.province = decrypt(driver.province);
				driver.governorate = decrypt(driver.governorate);
				driver.country = decrypt(driver.country);
				if (driver.addressLine2) {
					driver.addressLine2 = decrypt(driver.addressLine2);
				}

				for (var ord of orders) {
					ord.orderDate = new Date(decrypt(ord.orderDate));
					ord.totalCost = parseFloat(decrypt(ord.totalCost));

					req.input("order", sql.Char(32), ord.id);

					orderServices = await req.query(getOrderServices);
					orderServices = orderServices.recordset;

					orderFeedbacks = await req.query(getOrderFeedbacks);
					orderFeedbacks = orderFeedbacks.recordset;

					for (var os of orderServices) {
						os.quantity = parseInt(decrypt(os.quantity));
					}

					for (var ofb of orderFeedbacks) {
						ofb.message = decrypt(ofb.message);
					}

					ord.services = orderServices;
					ord.feedbacks = orderFeedbacks;

					delete ord.orderCode;
				}

				for (var i of issues) {
					i.issue = decrypt(i.issue);
				}

				for (var loc of orderLocations) {
					loc.longitude = parseFloat(loc.longitude);
					loc.latitude = parseFloat(loc.latitude);
					loc.addressLine1 = decrypt(loc.addressLine1);
					loc.city = decrypt(loc.city);
					loc.province = decrypt(loc.province);
					loc.governorate = decrypt(loc.governorate);
					loc.country = decrypt(loc.country);
					if (loc.addressLine2) {
						loc.addressLine2 = decrypt(loc.addressLine2);
					}
				}

				data = {
					token: token,
					user: user,
					driver: driver,
					orders: orders,
					deliveryIssues: issues,
					orderLocations: orderLocations
				};

				conn.emit("loginSuccess", data);

				console.log("200 - Ok\n");
				console.log(data);
				console.log();
			}
		} catch (err) {
			var error = {
				msg: "Error logging user in: " + err,
				statusCode: 400,
				statusMessage: "Bad Request"
			};

			conn.emit("loginError", error);
			console.log(error.statusCode + " - " + error.statusMessage + "\n");
			console.log(error.msg + "\n");
		}
	});

	conn.on("driverLocationChanged", function(driverId, lat, lng) {
		console.log("Client emit - " + driverId + " location changed: " + lat + ", " + lng + "\n");

		var latlng = {
			driverId: driverId,
			lat: lat,
			lng: lng
		};

		conn.broadcast.emit("updatedLocation", latlng);
	});

	conn.on("resetPassword", async function(mobile, newPass) {
		console.log("Client emit - reset password\n");

		var req = new sql.Request();
		req.input("mobile", sql.Int, mobile);

		var q = "select * from users where mobileNo=@mobile";

		var error;
		try {
			var results = await req.query(q);

			if (results.recordset.length === 0) {
				error = {
					msg: "This mobile number is not registered",
					statusCode: 401,
					statusMessage: "Unauthorized"
				};

				conn.emit("resetPasswordError", error);
				console.log(error.statusCode + " - " + error.statusMessage + "\n");
				console.log(error.msg + "\n");
			} else {
				var otp = Math.floor(Math.random() * (9999 - 2)) + 1;
				otp = otp.toString().padStart(4, '0');

				var res = await sendCode(otp, mobile, true);
				if (res.err) {
					error = {
						msg: "Error: Could not send OTP: " + res.err,
						statusCode: 500,
						statusMessage: "Internal Server Error"
					};

					conn.emit("resetPasswordError", error);
					console.log(error.statusCode + " - " + error.statusMessage + "\n");
					console.log(error.msg + "\n");
					console.log(res.err);
					console.log();
				} else {
					conn.handshake.otp = otp;
					conn.handshake.sendTime = res.sendTime;
					conn.handshake.mobile = mobile;
					conn.handshake.newPass = newPass;
					conn.emit("otpSent");
					console.log("OTP: " + otp + "\n");
				}
			}
		} catch (err) {
			error = {
				msg: "Error checking if user exists: " + err,
				statusCode: 400,
				statusMessage: "Bad Request"
			};

			conn.emit("resetPasswordError", error);
			console.log(error.statusCode + " - " + error.statusMessage + "\n");
			console.log(error.msg + "\n");
		}
	});

	conn.on("resetToNewPassword", async function() {
		console.log("Client emit - reset password confirmed\n");

		var mobile = conn.handshake.mobile;
		var newPass = conn.handshake.newPass;

		var req = new sql.Request();
		req.input("mobile", sql.Int, mobile);
		req.input("newPass", sql.Char(60), bcrypt.hashSync(newPass, 10));

		var q = "update users set password=@newPass where mobileNo=@mobile";
		try {
			await req.query(q);

			var res = {
				msg: "Password has been successfully changed",
				statusCode: 200,
				statusMessage: "OK"
			};

			conn.emit("resetPasswordSuccess", res);
			console.log(res.statusCode + " - " + res.statusMessage + "\n");
			console.log(res.msg + "\n");
		} catch (err) {
			var error = {
				msg: "Error changing password: " + err,
				statusCode: 400,
				statusMessage: "Bad Request"
			};

			conn.emit("resetPasswordError", error);
			console.log(error.statusCode + " - " + error.statusMessage + "\n");
			console.log(error.msg + "\n");
		}
	});

	conn.on("driverStatusChanged", async function(driverId, status) {
		console.log("Client emit - Driver's status changed\n");

		var res = {
			driverId: driverId,
			status: status
		};

		conn.broadcast.emit("changeDriverStatus", res);
	});

	conn.on("orderRequested", async function(orderJson) {
		console.log("Client emit - Order requested\n");

		try {
			var order = JSON.parse(orderJson);

			var consumerId = order.consumerId;
			var locationId = order.locationId;
			var deliveryOptionId = order.deliveryOptionId;
			var services = order.services.orderServices;
			var totalCost = order.totalCost;
			var climbStairs = order.climbStairs;

			var orderDate = new Date(Date.now());
			var idStr = consumerId + services + locationId + orderDate.toISOString();
			var id = crypto.createHash("md5").update(idStr).digest("hex");

			var r = new sql.Request();
			r.input("id", sql.Char(32), id);
			r.input("consumerId", sql.Char(32), consumerId);
			r.input("locationId", sql.Char(32), locationId);
			r.input("orderDate", sql.Char(144), encrypt(orderDate.toISOString()));
			r.input("deliveryOptionId", sql.Char(32), deliveryOptionId);
			r.input("totalCost", sql.NVarChar(112), encrypt(totalCost.toString()));
			r.input("climbStairs", sql.Bit, climbStairs);
			r.input("status", sql.NVarChar(20), "pending");
			r.input("arabicStatus", sql.NVarChar(60), "في الانتظار");

			var insertOrder = "insert into orders(id, consumerId, locationId, orderDate, " +
				"deliveryOptionId, climbStairs, totalCost, status, arabicStatus) values(@id, " +
				"@consumerId, @locationId, @orderDate, @deliveryOptionId, @climbStairs, @totalCost, " +
				"@status, @arabicStatus); " +
				"select * from orders where id=@id;";

			var newOrder = await r.query(insertOrder);
			newOrder = newOrder.recordset[0];

			for (var i = 0; i < services.length; i++) {
				r.input("service" + i, sql.Char(32), services[i].serviceId);
				r.input("quantity", sql.NVarChar(106), encrypt(services[i].quantity.toString()));
				var insert = "insert into orderServices values(@id, @service" + i + ", @quantity);";

				services[i].orderId = id;

				await r.query(insert);
			}

			var getConsumerInfo = "select fName, lName, displayPicThumb, displayPicUrl " +
				"from users where id=@consumerId";

			var getLocation = "select * from locations where id=@locationId";

			var consumerInfo = await r.query(getConsumerInfo);
			consumerInfo = consumerInfo.recordset[0];

			consumerInfo.fName = decrypt(consumerInfo.fName);
			consumerInfo.lName = decrypt(consumerInfo.lName);
			if (consumerInfo.displayPicUrl && consumerInfo.displayPicThumb) {
				consumerInfo.displayPicUrl = decrypt(consumerInfo.displayPicUrl);
				consumerInfo.displayPicThumb = decryptImage(consumerInfo.displayPicThumb);
			}

			var location = await r.query(getLocation);
			location = location.recordset[0];

			location.longitude = parseFloat(location.longitude);
			location.latitude = parseFloat(location.latitude);
			location.addressLine1 = decrypt(location.addressLine1);
			location.city = decrypt(location.city);
			location.province = decrypt(location.province);
			location.governorate = decrypt(location.governorate);
			location.country = decrypt(location.country);
			if (location.addressLine2) {
				location.addressLine2 = decrypt(location.addressLine2);
			}

			newOrder.orderDate = decrypt(newOrder.orderDate);
			newOrder.totalCost = parseFloat(decrypt(newOrder.totalCost));

			newOrder.services = services;
			newOrder.feedbacks = [];

			delete newOrder.orderCode;

			var orderPackage = {
				order: newOrder,
				consumerInfo: consumerInfo,
				orderLocation: location
			};

			conn.broadcast.emit("orderReceived", orderPackage);
			conn.emit("orderSent", newOrder);

			console.log("200 - OK\n");
			console.log("Order successfully sent\n");
		} catch (err) {
			var error = {
				msg: "Error sending order request: " + err,
				statusCode: 400,
				statusMessage: "Bad Request"
			};

			conn.emit("orderRequestedError", error);
			console.log(error.statusCode + " - " + error.statusMessage + "\n");
			console.log(error.msg + "\n");
		}
	});

	conn.on("orderAccepted", async function(orderId, driverId) {
		console.log("Client emit - Driver " + driverId + " accepted order " + orderId + "\n");

		var code = Math.floor(Math.random() * (9999 - 2)) + 1;
		code = code.toString().padStart(4, '0');

		var error;

		var req = new sql.Request();
		req.input("driver", sql.Char(32), driverId);
		req.input("order", sql.Char(32), orderId);
		req.input("code", sql.Char(4), code);
		req.input("status", sql.NVarChar(20), "accepted");
		req.input("arabicStatus", sql.NVarChar(60), "تم القبول");

		var setTransaction = "set transaction isolation level serializable;";
		var getData = "select u.mobileNo, o.status from users as u, orders as o " +
			"where o.id=@order and u.id=o.consumerId;";
		var transaction = "begin transaction;" +
			"update orders set driverId=@driver, orderCode=@code, status=@status, " +
			"arabicStatus=@arabicStatus where id=@order;" +
			"commit transaction;";
		try {
			var data = await req.query(transaction);
			var mobile = data.recordset[0].mobileNo;
			var status = data.recordset[0].status;

			if (status === "accepted") {
				error = {
					msg: "This order has already been accepted by another driver",
					statusCode: 400,
					statusMessage: "Bad Request"
				};

				conn.emit("orderAcceptedError", error);
				console.log(error.statusCode + " - " + error.statusMessage + "\n");
				console.log(error.msg + "\n");
			} else {
				await req.query(setTransaction);
				await req.query(transaction);
				await sendCode(code, mobile, false);

				conn.broadcast.emit("orderHadBeenAccepted", orderId);
				console.log("200 - OK\n");
				console.log("Order has been accepted successfully\n");
			}
		} catch (err) {
			error = {
				msg: "Error accepting order: " + err,
				statusCode: 400,
				statusMessage: "Bad Request"
			};

			conn.emit("orderAcceptedError", error);
			console.log(error.statusCode + " - " + error.statusMessage + "\n");
			console.log(error.msg + "\n");
		}
	});

	conn.on("attendingOrder", async function(orderId) {
		console.log("Client emit - Mark order as attending\n");

		var r = new sql.Request();
		r.input("order", sql.Char(32), orderId);
		r.input("status", sql.NVarChar(20), "attending");
		r.input("arabicStatus", sql.NVarChar(60), "في الطريق");

		var q = "update orders set status=@status, arabicStatus=@arabicStatus where id=@order;" +
			"select consumerId from orders where id=@order;";

		var consumer = await r.query(q);
		consumer = consumer.recordset[0].consumerId;

		conn.to(consumer).emit("notifyAttendingOrder", orderId);
	});

	conn.on("driverNearby", async function(orderId) {
		console.log("Client emit - Mark order as nearby\n");

		var r = new sql.Request();
		r.input("order", sql.Char(32), orderId);
		r.input("status", sql.NVarChar(20), "nearby");
		r.input("arabicStatus", sql.NVarChar(20), encrypt("قريب"));

		var q = "update orders set status=@status, arabicStatus=@arabicStatus where id=@order;" +
			"select consumerId from orders where id=@order;";

		var consumer = await r.query(q);
		consumer = consumer.recordset[0].consumerId;

		conn.to(consumer).emit("notifyDriverNearby", orderId);
	});

	conn.on("deliveryDone", async function(orderId) {
		console.log("Client emit - Inform consumer of delivery completion\n");

		var r = new sql.Request();
		r.input("order", sql.Char(32), orderId);
		r.input("status", sql.NVarChar(20), "Done");
		r.input("arabicStatus", sql.NVarChar(60), "تم التوصيل");

		var q = "update orders set status=@status, arabicStatus=@arabicStatus where id=@order;" +
			"select consumerId from orders where id=@order";

		var consumer = await (q);
		consumer = consumer.recordset[0];

		conn.to(consumer).emit("deliveryCompleted", orderId);
	});

	conn.on("deliveryIssue", async function(orderId, issue) {
		console.log("Client emit - Report an issue\n");

		var dateReported = new Date(Date.now());
		var id = crypto.createHash("md5").update(orderId + dateReported).digest("hex");

		var r = new sql.Request();
		r.input("id", sql.Char(32), id);
		r.input("orderId", sql.Char(32), orderId);
		r.input("dateReported", sql.DateTime, dateReported);
		r.input("issue", sql.NVarChar(500), encrypt(issue));

		var q = "insert into deliveryIssues (driverId, id, orderId, dateReported, issue) " +
			"select o.driverId, @id, @orderId, @dateReported, @issue from orders as o where o.id=@orderId; " +
			"select * from deliveryIssues where id=@id;";

		var getConsumer = "select consumerId from orders where id=@orderId";
		try {
			var reportedIssue = await r.query(q);
			reportedIssue = reportedIssue.recordset[0];

			var consumer = await r.query(getConsumer);
			consumer = consumer.recordset[0].consumerId;

			reportedIssue.issue = decrypt(reportedIssue.issue);

			conn.to(consumer).emit("issueReported", reportedIssue);
			conn.broadcast.emit("issueReported", reportedIssue);
			conn.emit("issueAddedToDb", reportedIssue.id);

			console.log("200 - OK\n");
			console.log("Issue reported successfully\n");
		} catch (err) {
			var error = {
				msg: "Error reporting delivery issue: " + err,
				statusCode: 400,
				statusMessage: "Bad Request"
			};

			conn.emit("deliveryIssueError", error);
			console.log(error.statusCode + " - " + error.statusMessage + "\n");
			console.log(error.msg + "\n");
		}
	});

	conn.on("updateConsumerProfile", async function(profile) {
		console.log("Client emit - Update consumer profile\n");

		var consumer = profile.userId;
		delete profile.userId;

		var error;

		var types = {
			mobileNo: sql.Int,
			email: sql.NVarChar(300),
			displayPicThumb: sql.VarBinary(sql.MAX),
			displayPicUrl: sql.NVarChar(500),
			gender: sql.NVarChar(100),
			dateOfBirth: sql.Char(144),
			age: sql.NVarChar(106),
			mainLocationId: sql.Char(32),
			mainLocationName: sql.NVarChar(40)
		};

		var r = new sql.Request();
		r.input("consumer", sql.Char(32), consumer);
		try {
			var keys = Object.keys(profile);

			if (keys.includes("displayPic")) {
				var img = Buffer.from(profile.displayPic, "base64");
				var imgName = "displayPic.png";
				var thumbName = "displayPicThumb.png";

				var dir = __dirname + "/Images/Users/" + consumer + "/";

				if (!fs.existsSync(dir)) {
					fs.mkdirSync(dir);
				}

				var baseUrl = imageFolderUrl + "/Users/" + consumer + "/";

				var thumb = await sharp(img).resize(150).toBuffer();
				fs.writeFileSync(dir + imgName, img);
				fs.writeFileSync(dir + thumbName, thumb);

				delete profile.displayPic;
				profile.displayPicThumb = encryptImage(thumb);
				profile.displayPicUrl = encrypt(baseUrl + imgName);
			}

			if (keys.includes("dateOfBirth")) {
				var dob = new Date(profile.dateOfBirth);
				profile.dateOfBirth = dob.toISOString();
				profile.age = (new Date(Date.now()).getYear() - dob.getYear()).toString();
			}

			var entries = Object.entries(profile);
			var intoUsers = [];
			var intoConsumers = [];

			for (var e of entries) {
				r.input(e[0], types[e[0]], e[1]);

				if (e[0].startsWith("mainLocation")) {
					e[1] = "@" + e[0];
					intoConsumers.push(e.join("="));
					continue;
				}

				if (!e[0].startsWith("displayPicThumb")) {
					e[1] = encrypt(e[1]);
				}

				if (e[0].startsWith("displayPic") || e[0].startsWith("email") ||
					e[0].startsWith("mobileNo")) {
					e[1] = "@" + e[0];
					intoUsers.push(e.join("="));
				} else {
					e[1] = "@" + e[0];
					intoConsumers.push(e.join("="));
				}
			}

			if (keys.includes("email") || keys.includes("displayPic") || keys.includes("gender") ||
				keys.includes("dateOfBirth") || keys.includes("mainLocationId") ||
				keys.includes("mainLocationName")) {
				var paramsUsers = intoUsers.join(", ");
				var paramsConsumers = intoConsumers.join(", ");

				var q;
				if (intoUsers.length !== 0 && intoConsumers.length !== 0) {
					q = "update users set " + paramsUsers + " where id=@consumer; " +
						"update consumers set " + paramsConsumers + "where userId=@consumer";
				} else if (intoUsers.length === 0 && intoConsumers.length !== 0) {
					q = "update consumers set " + paramsConsumers + "where userId=@consumer";
				} else if (intoUsers.length !== 0 && intoConsumers.length === 0) {
					q = "update users set " + paramsUsers + " where id=@consumer";
				}

				await r.query(q);

				if (!keys.includes("mobileNo")) {
					var resp = {
						msg: "User's profile was changed successfully",
						statusCode: 200,
						statusMessage: "OK"
					};

					conn.emit("userProfileChanged", resp);
					console.log(resp.statusCode + " - " + resp.statusMessage + "\n");
					console.log(resp.msg + "\n");
				}
			}

			if (keys.includes("mobileNo")) {
				var otp = Math.floor(Math.random() * (9999 - 2)) + 1;
				otp = otp.toString().padStart(4, '0');

				var res = await sendCode(otp, profile.mobileNo, true);
				if (res.err) {
					error = {
						msg: "Error: Could not send OTP: " + res.err,
						statusCode: 500,
						statusMessage: "Internal Server Error"
					};

					conn.emit("updateUserProfileError", error);
					console.log(error.statusCode + " - " + error.statusMessage + "\n");
					console.log(error.msg + "\n");
				} else {
					conn.handshake.otp = otp;
					conn.handshake.sendTime = res.sendTime;
					conn.handshake.mobileNo = profile.mobileNo;
					conn.handshake.user = consumer;
					conn.emit("otpSent");
					console.log("OTP: " + otp + "\n");
				}
			}
		} catch (err) {
			error = {
				msg: "Error: Could not update user's profile: " + err,
				statusCode: 400,
				statusMessage: "Bad Request"
			};

			conn.emit("updateUserProfileError", error);
			console.log(error.statusCode + " - " + error.statusMessage + "\n");
			console.log(error.msg + "\n");
		}
	});

	conn.on("updateDriverProfile", async function(profile) {
		console.log("Client emit - Update driver's profile\n");

		var driver = profile.userId;
		delete profile.userId;

		var types = {
			mobileNo: sql.Int,
			email: sql.NVarChar(300),
			displayPicThumb: sql.VarBinary(sql.MAX),
			displayPicUrl: sql.NVarChar(500),
			plateCode: sql.NVarChar(108),
			plateNumber: sql.NVarChar(116),
			bankName: sql.NVarChar(160),
			bankBranch: sql.NVarChar(140),
			bankAccountName: sql.NVarChar(200),
			bankAccountNo: sql.NVarChar(140),
			addressLine1: sql.NVarChar(500),
			addressLine2: sql.NVarChar(500),
			city: sql.NVarChar(200),
			province: sql.NVarChar(200),
			governorate: sql.NVarChar(200),
			country: sql.NVarChar(200),
			gasTransCert: sql.NVarChar(500),
			civilCerts: sql.NVarChar(500),
			applicationCreditForm: sql.NVarChar(500),
			cr: sql.NVarChar(500),
			occiCert: sql.NVarChar(500),
			sponsorId: sql.NVarChar(500),
			guaranteeCheque: sql.NVarChar(500),
			signDoc: sql.NVarChar(500),
			civilDefianceCert: sql.NVarChar(500),
			lpgSaleApproval: sql.NVarChar(500)
		};

		var entries = Object.entries(profile);
		var intoUsers = [];
		var intoDrivers = [];

		var dir = __dirname + "/Images/Users/" + driver + "/";
		var baseUrl = imageFolderUrl + "/Users/" + driver + "/";

		var r = new sql.Request();

		var img;
		var imgName;

		var changeMobile = false;
		var other = false;

		var error;

		try {
			for (var e of entries) {
				if (e[0].startsWith("displayPic")) {
					other = true;

					img = Buffer.from(profile.displayPic, "base64");
					imgName = "displayPic.png";
					var thumbName = "displayPicThumb.png";

					var thumb = await sharp(img).resize(150).toBuffer();
					fs.writeFileSync(dir + imgName, img);
					fs.writeFileSync(dir + thumbName, thumb);

					r.input("displayPicThumb", types.displayPicThumb, encryptImage(thumb));
					r.input("displayPicUrl", types.displayPicUrl, encrypt(baseUrl + imgName));

					intoUsers.push("displayPicThumb=@displayPicThumb");
					intoUsers.push("displayPicUrl=@displayPicUrl");
				} else if (e[0].startsWith("gasTransCert") || e[0].startsWith("civilCerts") ||
					e[0].startsWith("applicationCreditForm") || e[0].startsWith("cr") ||
					e[0].startsWith("occiCert") || e[0].startsWith("sponsorId") ||
					e[0].startsWith("guaranteeCheque") || e[0].startsWith("signDoc") ||
					e[0].startsWith("civilDefianceCert") || e[0].startsWith("lpgSaleApproval")) {
					other = true;

					img = fs.readFileSync(e[1]);
					imgName = e[0] + e[1].split('.')[e[1].split('.').length - 1];
					fs.writeFileSync(dir + imgName, img);

					r.input(e[0], types[e[0]], encrypt(baseUrl + imgName));
					intoDrivers.push(e[0] + "=@" + e[0]);
				} else if (e[0].startsWith("plateNumber")) {
					other = true;
					e[1] = encrypt(e[1].toString());
					r.input(e[0], types[e[0]], e[1]);
					intoDrivers.push(e[0] + "=@" + e[0]);
				} else if (e[0].startsWith("email")) {
					other = true;
					e[1] = encrypt(e[1]);
					r.input(e[0], types[e[0]], e[1]);
					intoUsers.push(e[0] + "=@" + e[0]);
				} else if (e[0].startsWith("mobileNo")) {
					changeMobile = true;
				} else {
					other = true;
					e[1] = encrypt(e[1]);
					r.input(e[0], types[e[0]], e[1]);
					intoDrivers.push(e[0] + "=@" + e[0]);
				}
			}

			if (other) {
				var paramsUsers = intoUsers.join(", ");
				var paramsDrivers = intoDrivers.join(", ");

				var q;
				if (intoUsers.length !== 0 && intoDrivers.length !== 0) {
					q = "update users set " + paramsUsers + " where id=@consumer; " +
						"update drivers set " + paramsDrivers + "where userId=@consumer";
				} else if (intoUsers.length === 0 && intoDrivers.length !== 0) {
					q = "update drivers set " + paramsDrivers + "where userId=@consumer";
				} else if (intoUsers.length !== 0 && intoDrivers.length === 0) {
					q = "update users set " + paramsUsers + " where id=@consumer";
				}

				await r.query(q);

				if (!changeMobile) {
					var resp = {
						msg: "User's profile was changed successfully",
						statusCode: 200,
						statusMessage: "OK"
					};

					conn.emit("userProfileChanged", resp);
					console.log(resp.statusCode + " - " + resp.statusMessage + "\n");
					console.log(resp.msg + "\n");
				}
			}

			if (changeMobile) {
				var otp = Math.floor(Math.random() * (9999 - 2)) + 1;
				otp = otp.toString().padStart(4, '0');

				var res = await sendCode(otp, profile.mobileNo, true);
				if (res.err) {
					error = {
						msg: "Error: Could not send OTP: " + res.err,
						statusCode: 500,
						statusMessage: "Internal Server Error"
					};

					conn.emit("updateUserProfileError", error);
					console.log(error.statusCode + " - " + error.statusMessage + "\n");
					console.log(error.msg + "\n");
				} else {
					conn.handshake.otp = otp;
					conn.handshake.sendTime = res.sendTime;
					conn.handshake.mobileNo = profile.mobileNo;
					conn.handshake.user = driver;
					conn.emit("otpSent");
					console.log("OTP: " + otp + "\n");
				}
			}
		} catch (err) {
			error = {
				msg: "Error: Could not update user's profile: " + err,
				statusCode: 400,
				statusMessage: "Bad Request"
			};

			conn.emit("updateUserProfileError", error);
			console.log(error.statusCode + " - " + error.statusMessage + "\n");
			console.log(error.msg + "\n");
		}
	});

	conn.on("updateMobileNo", async function() {
		console.log("Client emit - Update mobile number\n");

		var mobile = conn.handshake.mobileNo;
		var user = conn.handshake.user;

		var r = new sql.Request();
		r.input("user", sql.Char(32), user);
		r.input("mobile", sql.Int, mobile);

		var q = "update users set mobileNo=@mobile where id=@user";
		try {
			await r.query(q);

			var resp = {
				msg: "User's profile was changed successfully",
				statusCode: 200,
				statusMessage: "OK"
			};

			conn.emit("userProfileChanged", resp);
			console.log(resp.statusCode + " - " + resp.statusMessage + "\n");
			console.log(resp.msg + "\n");
		} catch (err) {
			error = {
				msg: "Error: Could not update user's profile: " + err,
				statusCode: 400,
				statusMessage: "Bad Request"
			};

			conn.emit("updateUserProfileError", error);
			console.log(error.statusCode + " - " + error.statusMessage + "\n");
			console.log(error.msg + "\n");
		}
	});

	conn.on("sendNotification", async function(notificationId) {
		console.log("Client emit - Send a notification\n");

		var r = new sql.Request();
		r.input("id", sql.Char(32), notificationId);

		var getNotif = "select * from notifications where id=@id";
		var getInteractiveNotif = "select * from interactiveNotifications where notificationId=@id";
		var getChoices = "select * from interactiveNotifChoices where interactiveNotifId=@id";

		try {
			var notif = await r.query(getNotif);
			notif = notif.recordset[0];

			if (notif.type === "interactive") {
				var interactiveNotif = await r.query(getInteractiveNotif);
				interactiveNotif = interactiveNotif.recordset[0];

				var choices = await r.query(getChoices);
				choices = choices.recordset;

				notif.correctChoice = interactiveNotif.correctChoice;
				notif.choices = choices;
			}

			conn.broadcast.emit("notificationSent", notif);

			console.log("200 - OK\n");
			console.log("Notification sent\n");
		} catch (err) {
			var error = {
				msg: "Error: Could not send notification: " + err,
				statusCode: 400,
				statusMessage: "Bad Request"
			};

			conn.emit("sendNotificationError", error);
			console.log(error.statusCode + " - " + error.statusMessage + "\n");
			console.log(error.msg + "\n");
		}
	});
});


// Reused functions
function sendCode(code, mobile, isOTP) {
	return new Promise(function(resolve, reject) {
		var url = "https://sms.ooredoo.com.om/User/bulkpush.asmx";

		var headers = {
			"Content-Type": "text/xml; charset=UTF-8"
		};

		var text;
		if (isOTP) {
			text = "OTP code: " + code + "\n The OTP expires in 60 seconds.";
		} else {
			text = "Your order has been accepted.\nThe order code is: " + code +
				"\nYou'll be asked for this code to complete the delivery.";
		}

		var params = {
			"soapenv:Envelope": {
				"$": {
					"xmlns:soapenv": "http://schemas.xmlsoap.org/soap/envelope/",
					"xmlns:web": "https://web.nawras.com.om/"
				},
				"soapenv:Body": {
					"web:SendSMS": {
						"web:UserName": process.env.SMS_GATEWAY_USER,
						"web:Password": process.env.SMS_GATEWAY_PASSWORD,
						"web:Message": text,
						"web:Priority": "1",
						"web:Sender": "mGas",
						"web:AppID": "1435",
						"web:SourceRef": "14",
						"web:MSISDNs": mobile
					}
				}
			}
		};

		var builder = new xml2js.Builder();
		var xml = builder.buildObject(params);

		var options = {
			rejectUnauthorized: false,
			url: url,
			method: "POST",
			headers: headers,
			body: xml
		};

		request(options, function(err, resp, body) {
			var res;

			if (err) {
				res = {
					err: err
				};
				resolve(res);
			} else {
				var xmlParser = new xml2js.Parser();
				xmlParser.parseString(body, function(err, result) {
					var sendRes = result["soap:Envelope"]["soap:Body"][0].SendSMSResponse[0].SendSMSResult[0];

					console.log(resp.statusCode + " - " + resp.statusMessage + "\n");
					console.log(sendRes);
					console.log();

					if (sendRes.StatusCode[0] !== "00") {
						res = {
							err: sendRes.StatusDesc
						};
						resolve(res);
					} else {
						res = {
							sendTime: Date.now()
						};
						resolve(res);
					}
				});
			}
		});
	});
}

function geocode(address, bounds) {
	return new Promise(function(resolve, reject) {
		address = address.replace(' ', '+');
		var url = "https://maps.googleapis.com/maps/api/geocode/json?address=" + address;

		var box = "";
		if (bounds) {
			box = bounds.southwest.lat + "," + bounds.southwest.lng + "|" +
				bounds.northeast.lat + "," + bounds.northeast.lng;
			box = "&bounds=" + box;
		}

		url = url + box + "&key=" + process.env.GOOGLE_MAPS_API_KEY;

		var options = {
			url: url,
			method: "GET"
		};

		request(options, function(err, res, body) {
			if (err) {
				reject(err);
			} else {
				resolve(body);
			}
		});
	});
}


// API routes
app.get("/activeLotteries", async function(req, res) {
	console.log("GET request - Get active lotteries request\n");

	var r = new sql.Request();
	r.input("today", sql.Date, new Date(Date.now()).toISOString());

	var q = "select * from lotteries where startDate <= @today and endDate >= @today";
	try {
		var lotteries = await r.query(q);
		lotteries = lotteries.recordset;

		for (var l of lotteries) {
			if (l.winningCode) {
				l.winningCode = decrypt(l.winningCode).slice(-8);
			}
		}

		res.json(lotteries);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(lotteries);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error getting active lotteries: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error getting active lotteries: " + err + "\n");
	}
});

app.post("/lottery", authorizeAdmin, async function(req, res) {
	console.log("POST request - Create lottery request\n");

	var startDate = req.body.startDate;
	var endDate = req.body.endDate;

	var id = crypto.createHash("md5").update(startDate + endDate).digest("hex");

	var r = new sql.Request();
	r.input("id", sql.Char(32), id);
	r.input("startDate", sql.Date, startDate);
	r.input("endDate", sql.Date, endDate);

	var q = "insert into lotteries(id, startDate, endDate) values(@id, @startDate, @endDate)";
	try {
		await r.query(q);

		res.json({
			msg: "Lottery created successfully"
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Lottery created successfully\n");
	} catch (err) {
		res.status(400).json({
			error: "Error while creating lottery: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error while creating lottery: " + err + "\n");
	}
});

app.get("/orders", authorizeAdmin, async function(req, res) {
	console.log("GET request - Get all orders request\n");

	var r = new sql.Request();
	var q = "select * from orders";

	try {
		var orders = await r.query(q);
		orders = orders.recordset;

		for (var o of orders) {
			r.input("orderId", sql.Char(32), o.id);

			var getServices = "select * from orderServices " +
				"where orderId=@orderId";

			var getFeedbacks = "select * from feedbacks where orderId=@orderId";

			var services = await r.query(getServices);
			services = services.recordset;

			var feedbacks = await r.query(getFeedbacks);
			feedbacks = feedbacks.recordset;

			for (var s of services) {
				s.quantity = parseInt(decrypt(s.quantity));
			}

			for (var f of feedbacks) {
				f.message = decrypt(f.message);
			}

			o.orderDate = new Date(decrypt(o.orderDate));
			o.totalCost = parseFloat(decrypt(o.totalCost));

			o.services = services;
			o.feedbacks = feedbacks;
		}

		res.json(orders);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(orders);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error retrieving all orders: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error retrieving all orders: " + err + "\n");
	}
});

app.get("/users", authorizeAdmin, async function(req, res) {
	console.log("GET request - Get all users request\n");

	var r = new sql.Request();
	var q = "select * from users";

	try {
		var users = await r.query(q);
		users = users.recordset;

		for (var u of users) {
			delete u.password;
			u.email = decrypt(u.email);
			u.idNo = parseInt(decrypt(u.idNo));
			u.fName = decrypt(u.fName);
			u.lName = decrypt(u.lName);

			if (u.displayPicThumb && u.displayPicUrl) {
				u.displayPicThumb = Array.prototype.slice.call(decryptImage(u.displayPicThumb), 0);
				u.displayPicUrl = decrypt(u.displayPicUrl);
			}
		}

		res.json(users);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(users);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error retrieving all users: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error retrieving all users: " + err + "\n");
	}
});

app.get("/consumers", authorizeAdmin, async function(req, res) {
	console.log("GET request - Get all consumers request\n");

	var r = new sql.Request();
	var q = "select * from consumers";

	try {
		var consumers = await r.query(q);
		consumers = consumers.recordset;

		for (var c of consumers) {
			if (c.gender) {
				c.gender = decrypt(c.gender);
			}

			if (c.dateOfBirth && c.age) {
				c.dateOfBirth = new Date(decrypt(c.dateOfBirth));
				c.age = parseInt(decrypt(c.age));
			}
		}

		res.json(consumers);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(consumers);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error retrieving all consumers: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error retrieving all consumers: " + err + "\n");
	}
});

app.get("/drivers", authorizeAdmin, async function(req, res) {
	console.log("GET request - Get all drivers request\n");

	var r = new sql.Request();
	var q = "select * from drivers";

	try {
		var drivers = await r.query(q);
		drivers = drivers.recordset;

		for (var d of drivers) {
			delete d.gasTransCert;
			delete d.civilCerts;
			delete d.applicationCreditForm;
			delete d.cr;
			delete d.occiCert;
			delete d.sponsorId;
			delete d.guaranteeCheque;
			delete d.civilDefianceCert;
			delete d.signDoc;
			delete d.lpgSaleApproval;
			d.plateCode = decrypt(d.plateCode);
			d.plateNumber = parseInt(decrypt(d.plateNumber));
			d.bankName = decrypt(d.bankName);
			d.bankBranch = decrypt(d.bankBranch);
			d.bankAccountName = decrypt(d.bankAccountName);
			d.bankAccountNo = decrypt(d.bankAccountNo);
			d.addressLine1 = decrypt(d.addressLine1);
			d.city = decrypt(d.city);
			d.province = decrypt(d.province);
			d.governorate = decrypt(d.governorate);
			d.country = decrypt(d.country);
			if (d.addressLine2) {
				d.addressLine2 = decrypt(d.addressLine2);
			}
		}

		res.json(drivers);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(drivers);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error retrieving all drivers: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error retrieving all drivers: " + err + "\n");
	}
});

app.post("/feedbacks", authorizeGeneral, async function(req, res) {
	console.log("POST request - Give feedback request\n");

	var orderId = req.body.orderId;
	var author = req.body.author;
	var message = req.body.message;

	var id = crypto.createHash("md5").update(orderId + author).digest("hex");

	var r = new sql.Request();
	r.input("id", sql.Char(32), id);
	r.input("orderId", sql.Char(32), orderId);
	r.input("author", sql.Char(32), author);
	r.input("message", sql.NVarChar(500), encrypt(message));

	var q = "insert into feedbacks(authorUserType, id, orderId, author, message) " +
		"select u.userType, @id, @orderId, @author, @message from users as u " +
		"where u.id=@author";
	try {
		await r.query(q);

		res.json({
			feedbackId: id
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Feedback submitted successfully\n");
	} catch (err) {
		res.status(400).json({
			error: "Error submitting feedback: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error submitting feedback: " + err + "\n");
	}
});

app.get("/:order/feedback", authorizeGeneral, async function(req, res) {
	console.log("GET request - Get order's feedback request\n");

	try {
		var order = req.params.order;

		var r = new sql.Request();
		r.input("order", sql.Char(32), order);

		var q = "select * from feedbacks where orderId=@order";
		var getAutorInfo = "select fName, lName, displayPicUrl, displayPicThumb from users " +
			"where id=@author";

		var feedbacks = await r.query(q);
		feedbacks = feedbacks.recordset;

		var authors = [];
		for (var f of feedbacks) {
			r.input("author", sql.Char(32), f.author);

			var authorInfo = await r.query(getAutorInfo);
			authorInfo = authorInfo.recordset[0];

			authorInfo.fName = decrypt(authorInfo.fName);
			authorInfo.lName = decrypt(authorInfo.lName);

			if (authorInfo.displayPicThumb && authorInfo.displayPicUrl) {
				authorInfo.displayPicUrl = decrypt(authorInfo.displayPicUrl);
				authorInfo.displayPicThumb = decryptImage(authorInfo.displayPicThumb);
			}

			authors.push(authorInfo);

			f.message = decrypt(f.message);
		}

		var feedbackPackage = {
			feedbacks: feedbacks,
			authors: authors
		};

		res.json(feedbackPackage);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(feedbacks);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error getting feedback for order: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error getting feedback for order: " + err + "\n");
	}
});

app.post("/:user/cards", authorizeConsumer, async function(req, res) {
	console.log("POST request - Add a card for a consumer request\n");

	var owner = req.params.user;
	var cardNo = req.body.cardNo;
	var expDateMonth = req.body.expDateMonth;
	var expDateYear = req.body.expDateYear;
	var cvv = req.body.cvv;

	var id = crypto.createHash("md5").update(owner + cardNo).digest("hex");

	var r = new sql.Request();
	r.input("id", sql.Char(32), id);
	r.input("owner", sql.Char(32), owner);
	r.input("cardNo", sql.NVarChar(132), encrypt(cardNo));
	r.input("expDateMonth", sql.NVarChar(104), encrypt(expDateMonth.toString()));
	r.input("expDateYear", sql.NVarChar(108), encrypt(expDateYear.toString()));
	r.input("cvv", sql.NVarChar(106), encrypt(cvv.toString()));

	var q = "insert into bankCards values(@id, @owner, @cardNo, @expDateMonth, @expDateYear, @cvv)";
	try {
		await r.query(q);

		res.json({
			cardId: id
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Card added successfully\n");
	} catch (err) {
		res.status(400).json({
			error: "Error adding card for consumer: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error adding card for consumer: " + err + "\n");
	}
});

app.post("/promotionCodes", authorizeAdmin, async function(req, res) {
	console.log("POST request - Generate promotion codes request\n");

	var number = req.body.number;
	var lottery = req.body.lottery;

	var r = new sql.Request();
	r.input("lotteryId", sql.Char(32), lottery);
	r.input("used", sql.Bit, 0);
	var findLottery = "select lotteryId from promotionCodes where lotteryId=@lotteryId";
	var selectEndDate = "select endDate from lotteries where id=@lotteryId";
	var getSerial = "select * from promotionCodes where lotteryId=@lotteryId";
	var insert = "insert into promotionCodes(lotteryId, code, expDate, used) " +
		"values(@lotteryId, @code, @expDate, @used)";
	var reseed = "dbcc checkident(promotionCodes, reseed, 0);";

	try {
		var lotteries = await r.query(findLottery);
		lotteries = lotteries.recordset;

		if (lotteries.length === 0) {
			await r.query(reseed);
		}

		var expDate = await r.query(selectEndDate);
		expDate = expDate.recordset[0].endDate;
		r.input("expDate", sql.Char(144), encrypt(expDate.toISOString()));

		var serial = await r.query(getSerial);
		serial = serial.recordset.length;

		var codes = [];
		var n = serial + number;
		for (var i = serial; i < n; i++) {
			var code = crypto.createHash("md5").update(lottery + i).digest("hex").slice(0, 8);
			codes.push(code);
			r.input("code", sql.NVarChar(116), encrypt("Pc" + code));
			await r.query(insert);
		}

		res.json({
			codes: codes
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(codes);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error generating promotion codes: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error generating promotion codes: " + err + "\n");
	}
});

app.get("/promotionCodes", authorizeAdmin, async function(req, res) {
	console.log("GET request - Get promotion codes request\n");

	var r = new sql.Request();
	var q = "select * from promotionCodes";

	try {
		var codes = await r.query(q);
		codes = codes.recordset;

		for (var c of codes) {
			c.code = decrypt(c.code).slice(-8);
			c.expDate = new Date(decrypt(c.expDate));
		}

		res.json(codes);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(codes);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error retrieving promotion codes: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error retrieving promotion codes: " + err + "\n");
	}
});

app.post("/:user/promotionCodes", authorizeConsumer, async function(req, res) {
	console.log("POST request - Use promotion code request\n");

	var code = req.body.code;
	var consumer = req.params.user;

	var r = new sql.Request();
	r.input("consumer", sql.Char(32), consumer);
	r.input("used", sql.Bit, 1);

	var getCodes = "select code, used from promotionCodes";

	var update = "update promotionCodes set used=@used, owner=@consumer where code=@code";
	try {
		var codes = await r.query(getCodes);
		codes = codes.recordset;

		var encrypted;
		var used;
		for (var c of codes) {
			if (decrypt(c.code).slice(-8) === code) {
				encrypted = c.code;
				used = c.used;
			}
		}

		var msg;
		if (used) {
			res.status(409).json({
				error: "Error: This promotion code has already been used",
				arabicError: "خطأ: تم استعمال هذا الرمز الترويجي مسبقا"
			});

			msg = "Error: This promotion code has already been used";
		} else {
			r.input("code", sql.NVarChar(116), encrypted);

			await r.query(update);

			res.json({
				msg: "Promotion code was used successfully",
				arabicMsg: "تم استعمال الرمز الترويجي بنجاح"
			});

			msg = "Promotion code was used successfully";
		}

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(msg + "\n");
	} catch (err) {
		res.status(400).json({
			error: "Error using promotion code: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error using promotion code: " + err + "\n");
	}
});

app.get("/lotteries", authorizeAdmin, async function(req, res) {
	console.log("GET request - Get all lotteries request\n");

	var r = new sql.Request();
	var q = "select * from lotteries";

	try {
		var lotteries = await r.query(q);
		lotteries = lotteries.recordset;

		for (var l of lotteries) {
			if (l.winningCode) {
				l.winningCode = decrypt(l.winningCode).slice(-8);
			}
		}

		res.json(lotteries);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(lotteries);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error retrieving all lotteries: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error retrieving all lotteries: " + err + "\n");
	}
});

app.get("/services", authorizeGeneral, async function(req, res) {
	console.log("GET request - Get services request\n");

	var r = new sql.Request();
	var q = "select * from services";

	try {
		var services = await r.query(q);
		services = services.recordset;

		for (var s of services) {
			s.type = decrypt(s.type);
			s.arabicType = decrypt(s.arabicType);
			s.charge = parseFloat(decrypt(s.charge));
			s.dateModified = new Date(decrypt(s.dateModified));

			if (s.cylinderSize && s.arabicCylinderSize) {
				s.cylinderSize = decrypt(s.cylinderSize);
				s.arabicCylinderSize = decrypt(s.arabicCylinderSize);
			}
		}

		res.json(services);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(services);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error retrieving services: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error retrieving services: " + err + "\n");
	}
});

app.post("/services", authorizeAdmin, async function(req, res) {
	console.log("POST request - Add or update services request\n");

	var type = req.body.type;
	var arabicType = req.body.arabicType;
	var size = req.body.cylinderSize;
	var arabicSize = req.body.arabicCylinderSize;
	var charge = req.body.charge;

	var dateModified = new Date(Date.now());
	var id = crypto.createHash("md5").update(type + size + dateModified.toISOString()).digest("hex");

	var r = new sql.Request();
	r.input("id", sql.Char(32), id);
	r.input("type", sql.NVarChar(200), encrypt(type));
	r.input("arabicType", sql.NVarChar(500), encrypt(arabicType));
	r.input("charge", sql.NVarChar(114), encrypt(charge.toString()));
	r.input("dateModified", sql.Char(144), encrypt(dateModified.toISOString()));
	if (size && arabicSize) {
		r.input("size", sql.NVarChar(110), encrypt(size));
		r.input("arabicSize", sql.NVarChar(200), encrypt(arabicSize));
	} else {
		r.input("size", sql.NVarChar(110), size);
		r.input("arabicSize", sql.NVarChar(200), arabicSize);
	}

	var q = "insert into services values(@id, @type, @arabicType, @size, @arabicSize, " +
		"@charge, @dateModified)";
	try {
		await r.query(q);

		res.json({
			msg: "Service added or updated successfully"
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Service added successfully\n");
	} catch (err) {
		res.status(400).json({
			error: "Error adding or updated service: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error sdding service: " + err + "\n");
	}
});

app.post("/:user/verifyOrderCode", authorizeDriver, async function(req, res) {
	console.log("POST request - Verify order code request\n");

	var driver = req.params.user;
	var order = req.body.order;
	var code = req.body.code;

	var r = new sql.Request();
	r.input("order", sql.Char(32), order);
	r.input("status", sql.NVarChar(20), "delivered");

	var q = "select driverId, orderCode from orders where id=@order";
	var update = "update orders set status=@status where id=@order";
	try {
		var stored = await r.query(q);
		stored = stored.recordset[0];

		var msg;
		if (driver === stored.driverId && code === stored.orderCode) {
			msg = "Confirmed";
			await r.query(update);

			res.json({
				msg: msg
			});
		} else {
			msg = "Error: The code does not match";

			res.status(400).json({
				error: msg
			});
		}

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(msg + "\n");
	} catch (err) {
		res.status(400).json({
			error: "Error verifying order code: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error verifying order code: " + err + "\n");
	}
});

app.post("/notifications", authorizeAdmin, async function(req, res) {
	console.log("POST request - create push notification request\n");

	var title = req.body.title;
	var arabicTitle = req.body.arabicTitle;
	var text = req.body.text;
	var arabicText = req.body.arabicText;
	var imgUrl = req.body.imgUrl;
	var scheduledTime = req.body.scheduledTime;

	var id = crypto.createHash("md5").update(title + text).digest("hex");

	var img = fs.readFileSync(imgUrl);
	var imgName = "image" + imgUrl.split('.')[imgUrl.split('.').length - 1];
	var dir = __dirname + "/Images/Notifications/" + id + "/";

	if (!fs.existsSync(dir)) {
		fs.mkdirSync(dir);
	}

	fs.writeFileSync(dir + imgName, img);

	var baseUrl = imageFolderUrl + "/Notifications/" + id + "/";

	var r = new sql.Request();
	r.input("id", sql.Char(32), id);
	r.input("title", sql.NVarChar(30), title);
	r.input("arabicTitle", sql.NVarChar(80), arabicTitle);
	r.input("text", sql.NVarChar(200), text);
	r.input("arabicText", sql.NVarChar(500), arabicText);
	r.input("img", sql.NVarChar(200), baseUrl + imgName);
	r.input("scheduledTime", sql.DateTime, new Date(scheduledTime));
	r.input("type", sql.NVarChar(11), "static");

	var q = "insert into notifications values(@id, @title, @arabicTitle, @text, @arabicText, " +
		"@img, @scheduledTime, @type)";
	try {
		await r.query(q);

		res.json({
			msg: "Notification created successfully"
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Notification created successfully\n");
	} catch (err) {
		res.status(400).json({
			error: "Error creating notification: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error creating notification: " + err + "\n");
	}
});

app.post("/interactiveNotifications", authorizeAdmin, async function(req, res) {
	console.log("POST request - create interactive push notification request\n");

	var title = req.body.title;
	var arabicTitle = req.body.arabicTitle;
	var text = req.body.text;
	var arabicText = req.body.arabicText;
	var imgUrl = req.body.imgUrl;
	var scheduledTime = req.body.scheduledTime;
	var correctChoice = req.body.correctChoiceTitle;
	var choices = req.body.choices;

	var id = crypto.createHash("md5").update(title + text).digest("hex");

	var img = fs.readFileSync(imgUrl);
	var imgName = "image" + imgUrl.split('.')[imgUrl.split('.').length - 1];
	var dir = __dirname + "/Images/Notifications/" + id + "/";

	if (!fs.existsSync(dir)) {
		fs.mkdirSync(dir);
	}

	fs.writeFileSync(dir + imgName, img);

	var r = new sql.Request();
	r.input("id", sql.Char(32), id);
	r.input("title", sql.NVarChar(30), title);
	r.input("arabicTitle", sql.NVarChar(80), arabicTitle);
	r.input("text", sql.NVarChar(500), text);
	r.input("arabicText", sql.NVarChar(200), arabicText);
	r.input("img", sql.NVarChar(200), dir + imgName);
	r.input("scheduledTime", sql.DateTime, new Date(scheduledTime));
	r.input("type", sql.NVarChar(11), "interactive");
	r.input("correctChoice", sql.NVarChar(20), correctChoice);

	var q = "insert into notifications values(@id, @title, @arabicTitle, @text, @arabicText, " +
		"@img, @scheduledTime, @type); " +
		"insert into interactiveNotifications(notificationId) values(@id); ";

	var x = 0;
	for (var c of choices) {
		var choiceTitle = c.title;
		var choiceArabicTitle = c.arabicTitle;
		var desc = c.description;
		var arabicDesc = c.arabicDesc;

		var choiceId = crypto.createHash("md5").update(id + title + text).digest("hex");

		r.input("choiceId" + x, sql.Char(32), choiceId);
		r.input("choiceTitle" + x, sql.NVarChar(20), choiceTitle);
		r.input("choiceArabicTitle" + x, sql.NVarChar(20), choiceArabicTitle);
		r.input("desc" + x, sql.NVarChar(200), desc);
		r.input("arabicDesc" + x, sql.NVarChar(200), arabicDesc);

		if (c.imgUrl) {
			var choicImgUrl = c.imgUrl;
			var choiceImg = fs.readFileSync(choicImgUrl);
			var choiceImgName = choiceTitle + choicImgUrl.split('.')[choicImgUrl.split('.').length - 1];
			fs.writeFileSync(dir + choiceImgName, choiceImg);
			r.input("choiceImg" + x, sql.NVarChar(200), dir + choiceImgName);
		} else {
			r.input("choiceImg" + x, sql.NVarChar(200), null);
		}

		q += "insert into interactiveNotifChoices(id, interactiveNotifId, title, arabicTitle, " +
			"description, arabicDescription, image) " +
			"values(@choiceId" + x + ", @id" + x + ", @choiceTitle" + x + ", @arabicTitle" + x +
			", @desc" + x + ", @arabicDesc" + x + ", @choiceImg" + x + "); ";

		x++;
	}

	q += "insert into interactiveNotifications(correctChoice, notificationId) " +
		"select c.id, @id from interactiveNotifChoices as c where c.title=@correctChoice " +
		"and c.interactiveNotifId=@id";

	try {
		await r.query(q);

		res.json({
			msg: "Interactive notification created successfully"
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Interactive notification created successfully\n");
	} catch (err) {
		res.status(400).json({
			error: "Error creating interactive notification: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error creating interactive notification: " + err + "\n");
	}
});

app.get("/deliveryIssues", authorizeAdmin, async function(req, res) {
	console.log("GET request - Get all delivery issues request\n");

	var r = new sql.Request();
	var q = "select * from deliveryIssues";

	try {
		var issues = await r.query(q);
		issues = issues.recordset;

		for (var i of issues) {
			i.issue = decrypt(i.issue);
		}

		res.json(issues);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(issues);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error getting delivery issues: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error getting delivery issues: " + err + "\n");
	}
});

app.get("/images/:folder/:id/:image", async function(req, res) {
	console.log("GET request - Get image request\n");

	var dir = __dirname + "/Images/";
	var folder = req.params.folder;
	var id = req.params.id;
	var name = req.params.image;

	var path = dir + folder + "/" + id + "/" + name;

	var img = fs.readFileSync(path);
	res.set("Content-Type", "image/png");
	res.end(img, "binary");
});

app.post("/adminToken", async function(req, res) {
	console.log("GET request - Generate admin token request\n");

	var secret = req.body.secret;

	if (secret === process.env.ADMIN_AUTH_SECRET) {
		var payload = {
			userType: "admin"
		};
		var exp = {
			expiresIn: "1d"
		};
		var token = jwt.sign(payload, process.env.JWT_SECRET, exp);

		var resp = {
			token: token,
			expiresIn: "1d"
		};

		res.json(resp);
		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(resp);
		console.log();
	} else {
		var err = {
			msg: "Admin secret is incorrect"
		};

		res.status(403).json(err);
		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(err);
		console.log();
	}
});

app.get("/notifications", authorizeAdmin, async function(req, res) {
	console.log("GET request - Get all push notifications request\n");

	var r = new sql.Request();
	var q = "select * from notifications";

	try {
		var notifs = await r.query(q);
		notifs = notifs.recordset;

		res.json(notifs);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(notifs);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error getting notifications: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error getting notifications: " + err + "\n");
	}
});

app.get("/interactiveNotifications", authorizeAdmin, async function(req, res) {
	console.log("GET request - Get all interactive notifications request\n");

	var r = new sql.Request();
	r.input("type", sql.NVarChar(11), "interactive");

	var getNotifs = "select * from notifications where type=@type";
	var getCorrectChoice = "select correctChoice from interactiveNotifications " +
		"where notificationId=@id";
	var getChoices = "select * from interactiveNotifChoices where interactiveNotifId=@id";

	try {
		var notifs = await r.query(getNotifs);
		notifs = notifs.recordset;

		for (var n of notifs) {
			r.input("id", sql.Char(32), n.id);

			var correctChoice = await r.query(getCorrectChoice);
			correctChoice = correctChoice.recordset[0];

			var choices = await r.query(getChoices);
			choices = choices.recordset;

			n.correctChoice = correctChoice;
			n.choices = choices;
		}

		res.json(notifs);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(notifs);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error getting interactive notifications: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error getting interactive notifications: " + err + "\n");
	}
});

app.post("/:notification/submitChoice", authorizeGeneral, async function(req, res) {
	console.log("POST request - Submit interactive notification choice request\n");

	var notifId = req.params.notification;
	var choiceId = req.body.choiceId;

	var r = new sql.Request();
	r.input("notif", sql.Char(32), notifId);
	r.input("choice", sql.Char(32), choicefId);

	var setTransaction = "set transaction isolation level serializable;";
	var transaction = "begin transaction;" +
		"update interactiveNotifChoices set selectionsNo=selectionsNo+1 where id=@choice;" +
		"commit transaction;";
	var getNumSelections = "select id, selectionsNo from interactiveNotifChoices " +
		"where interactiveNotifId=@notif;";

	try {
		await r.query(setTransaction);
		await r.query(transaction);

		var numSelections = await r.query(getNumSelections);
		numSelections = numSelections.recordset;

		var selections = {};
		for (var s of numSelections) {
			selections[s.id] = s.selectionsNo;
		}

		res.json(selections);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(selections);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error submitting choice: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error submitting choice: " + err + "\n");
	}
});

app.post("/:user/locations", authorizeConsumer, async function(req, res) {
	console.log("POST request - Add new location for consumer request\n");

	try {
		var consumer = req.params.user;

		var id = req.body.latitude.toString() + req.body.longitude.toString() + consumer;
		id = crypto.createHash("md5").update(id).digest("hex");

		var addressLine1 = req.body.addressLine1;
		var lng = req.body.longitude;
		var lat = req.body.latitude;
		var name = req.body.name;

		var location = addressLine1.split(", ");

		var r = new sql.Request();
		r.input("locId", sql.Char(32), id);
		r.input("consumerId", sql.Char(32), consumer);
		r.input("lng", sql.NVarChar(140), encrypt(lng.toString()));
		r.input("lat", sql.NVarChar(140), encrypt(lat.toString()));
		r.input("address", sql.NVarChar(500), encrypt(addressLine1));
		r.input("city", sql.NVarChar(200), encrypt(location[3]));
		r.input("province", sql.NVarChar(200), encrypt(location[2]));
		r.input("governorate", sql.NVarChar(200), encrypt(location[1]));
		r.input("country", sql.NVarChar(200), encrypt(location[0]));
		r.input("name", sql.NVarChar(40), name);

		var q = "insert into locations(id, longitude, latitude, addressLine1, city, province, " +
			"governorate, country) values(@locId, @lng, @lat, @address, @city, @province, " +
			"@governorate, @country);" +
			"insert into consumerLocations values(@consumerId, @locId, @name)";

		await r.query(q);

		var newLocation = {
			id: id,
			longitude: lng,
			latitude: lat,
			addressLine1: addressLine1,
			addressLine2: null,
			city: location[3],
			province: location[2],
			governorate: location[1],
			country: location[0],
			locationName: name
		};

		res.json(newLocation);

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(newLocation);
		console.log();
	} catch (err) {
		res.status(400).json({
			error: "Error adding location: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error adding location: " + err + "\n");
	}
});

app.patch("/:user/locations/:location", authorizeConsumer, async function(req, res) {
	console.log("PATCH request - Edit a location request\n");

	var consumer = req.params.user;
	var location = req.params.location;

	var types = {
		addressLine1: sql.NVarChar(500),
		addressLine2: sql.NVarChar(500),
		locationName: sql.NVarChar(40)
	};

	var name = false;
	var entries = Object.entries(req.body);
	var joint = [];

	var r = new sql.Request();
	r.input("location", sql.Char(32), location);
	r.input("consumer", sql.Char(32), consumer);

	for (var e of entries) {
		if (e[0] === "locationName") {
			name = true;
			continue;
		}

		e[1] = encrypt(e[1]);
		r.input(e[0], types[e[0]], e[1]);
		joint.push(e[0] + "=@" + e[0]);
	}

	var params = joint.join(", ");

	var updateLoc = "update locations set " + params + " where id=@location";
	var updateConsumerLoc = "update consumerLocations set locationName=@name " +
		"where locationId=@location and consumerId=@consumer";

	try {
		if (joint.length !== 0) {
			await r.query(updateLoc);
		}

		if (name) {
			r.input("name", types.locationName, req.body.locationName);
			await r.query(updateConsumerLoc);
		}

		res.json({
			msg: "Location was successfully updated"
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Location was successfully updated\n");
	} catch (err) {
		res.status(400).json({
			error: "Error updating location: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error updating location: " + err + "\n");
	}
});

app.delete("/:user/cards/:card", authorizeConsumer, async function(req, res) {
	console.log("DELETE request - Delete a card request\n");

	var consumer = req.params.user;
	var card = req.params.card;

	var r = new sql.Request();
	r.input("card", sql.Char(32), card);
	r.input("owner", sql.Char(32), consumer);

	var q = "delete from bankCards where id=@card and owner=@owner";
	try {
		await r.query(q);

		res.json({
			msg: "Card record was deleted successfully"
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Card record was deleted successfully\n");
	} catch (err) {
		res.status(400).json({
			error: "Error deleting bank card record: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error deleting bank card record: " + err + "\n");
	}
});

app.delete("/:user/locations/:location", authorizeConsumer, async function(req, res) {
	console.log("DELETE request - Delete a location request\n");

	var consumer = req.params.user;
	var location = req.params.location;

	var r = new sql.Request();
	r.input("consumer", sql.Char(32), consumer);
	r.input("loc", sql.Char(32), location);

	var q = "delete from consumerLocations where consumerId=@consumer and locationId=@loc";
	try {
		await r.query(q);

		res.json({
			msg: "Location record was deleted successfully"
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Location record was deleted successfully\n");
	} catch (err) {
		res.status(400).json({
			error: "Error deleting location record: " + err
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Error deleting location record: " + err + "\n");
	}
});

app.post("/tokenExpiry", async function(req, res) {
	console.log("GET request - Get if token expired request\n");

	try {
		var token = req.body.token;

		jwt.verify(token, process.env.JWT_SECRET, function(err, payload) {
			var result;
			if (err) {
				if (err.name === 'TokenExpiredError') {
					result = {
						expired: true
					};

					res.json(result);

					console.log(res.statusCode + " - " + res.statusMessage + "\n");
					console.log(result);
					console.log();
				} else {
					result = {
						error: "Error: Unable to verify token expiry"
					};

					res.status(400).json(result);

					console.log(res.statusCode + " - " + res.statusMessage + "\n");
					console.log(result);
					console.log();
				}
			} else {
				result = {
					expired: false
				};

				res.json(result);

				console.log(res.statusCode + " - " + res.statusMessage + "\n");
				console.log(result);
				console.log();
			}
		});
	} catch (err) {
		res.status(400).json({
			error: "Error: Unable to verify token expiry"
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(result);
		console.log();
	}
});

app.get("/guestLogin", async function(req, res) {
	console.log("GET request - Guest token generation request\n");

	var payload = {
		userType: "guest"
	};

	var token = jwt.sign(payload, process.env.JWT_SECRET);

	var resp = {
		token: token,
		userType: "guest"
	};

	res.json(resp);
	console.log(res.statusCode + " - " + res.statusMessage + "\n");
	console.log(resp);
	console.log();
});

/*app.post("/test", async function(req, res) {
	console.log("POST request - Add test driver request\n");

	try {
		var driver = req.body;

		var mobile = driver.mobileNo;
		var pass = driver.password;
		var email = driver.email;
		var idNo = driver.idNo;
		var fname = driver.fname;
		var lname = driver.lname;

		var plateCode = driver.plateCode;
		var plateNumber = driver.plateNumber;
		var bankName = driver.bankName;
		var bankBranch = driver.bankBranch;
		var bankAccountName = driver.bankAccountName;
		var bankAccountNo = driver.bankAccountNo;
		var addressLine1 = driver.addressLine1;
		var addressLine2 = driver.addressLine2;
		var city = driver.city;
		var province = driver.province;
		var governorate = driver.governorate;
		var country = driver.country;
		var gasTransCert = driver.gasTransCert;
		var civilCerts = driver.civilCerts;
		var applicationCreditForm = driver.applicationCreditForm;
		var cr = driver.cr;
		var occiCert = driver.occiCert;
		var sponsorId = driver.sponsorId;
		var guaranteeCheque = driver.guaranteeCheque;
		var signDoc = driver.signDoc;
		var civilDefianceCert = driver.civilDefianceCert;
		var lpgSaleApproval = driver.lpgSaleApproval;

		var id = crypto.createHash("md5").update(idNo.toString()).digest("hex");

		var gasTransCertImg = fs.readFileSync(gasTransCert);
		var civilCertsImg = fs.readFileSync(civilCerts);
		var applicationCreditFormImg = fs.readFileSync(applicationCreditForm);
		var crImg = fs.readFileSync(cr);
		var occiCertImg = fs.readFileSync(occiCert);
		var sponsorIdImg = fs.readFileSync(sponsorId);
		var guaranteeChequeImg = fs.readFileSync(guaranteeCheque);
		var signDocImg = fs.readFileSync(signDoc);
		var civilDefianceCertImg = fs.readFileSync(civilDefianceCert);
		var lpgSaleApprovalImg = fs.readFileSync(lpgSaleApproval);

		var gasTransCertImgName = "gasTransCert." +
			gasTransCert.split('.')[gasTransCert.split('.').length - 1];
		var civilCertsImgName = "civilCerts." +
			civilCerts.split('.')[civilCerts.split('.').length - 1];
		var applicationCreditFormImgName = "applicationCreditForm." +
			applicationCreditForm.split('.')[applicationCreditForm.split('.').length - 1];
		var crImgName = "cr." + cr.split('.')[cr.split('.').length - 1];
		var occiCertImgName = "occiCert." + occiCert.split('.')[occiCert.split('.').length - 1];
		var sponsorIdImgName = "sponsorId." + sponsorId.split('.')[sponsorId.split('.').length - 1];
		var guaranteeChequeImgName = "guaranteeCheque." +
			guaranteeCheque.split('.')[guaranteeCheque.split('.').length - 1];
		var signDocImgName = "signDoc." + signDoc.split('.')[signDoc.split('.').length - 1];
		var civilDefianceCertImgName = "civilDefianceCert." +
			civilDefianceCert.split('.')[civilDefianceCert.split('.').length - 1];
		var lpgSaleApprovalImgName = "lpgSaleApproval." +
			lpgSaleApproval.split('.')[lpgSaleApproval.split('.').length - 1];

		var dir = __dirname + "/Images/Users/" + id + "/";

		if (!fs.existsSync(dir)) {
			fs.mkdirSync(dir);
		}

		fs.writeFileSync(dir + gasTransCertImgName, gasTransCertImg);
		fs.writeFileSync(dir + civilCertsImgName, civilCertsImg);
		fs.writeFileSync(dir + applicationCreditFormImgName, applicationCreditFormImg);
		fs.writeFileSync(dir + crImgName, crImg);
		fs.writeFileSync(dir + occiCertImgName, occiCertImg);
		fs.writeFileSync(dir + sponsorIdImgName, sponsorIdImg);
		fs.writeFileSync(dir + guaranteeChequeImgName, guaranteeChequeImg);
		fs.writeFileSync(dir + signDocImgName, signDocImg);
		fs.writeFileSync(dir + civilDefianceCertImgName, civilDefianceCertImg);
		fs.writeFileSync(dir + lpgSaleApprovalImgName, lpgSaleApprovalImg);

		var baseUrl = imageFolderUrl + "/Users/" + id + "/";

		var request = new sql.Request();
		request.input("id", sql.Char(32), id);
		request.input("mobile", sql.Int, mobile);
		request.input("pass", sql.Char(60), bcrypt.hashSync(pass, 10));
		request.input("email", sql.NVarChar(300), encrypt(email));
		request.input("idNo", sql.NVarChar(120), encrypt(idNo.toString()));
		request.input("fname", sql.NVarChar(140), encrypt(fname));
		request.input("lname", sql.NVarChar(140), encrypt(lname));
		request.input("userType", sql.NVarChar(8), "driver");
		request.input("plateCode", sql.NVarChar(108), encrypt(plateCode));
		request.input("plateNumber", sql.NVarChar(116), encrypt(plateNumber.toString()));
		request.input("bankName", sql.NVarChar(160), encrypt(bankName));
		request.input("bankBranch", sql.NVarChar(140), encrypt(bankBranch));
		request.input("bankAccountName", sql.NVarChar(200), encrypt(bankAccountName));
		request.input("bankAccountNo", sql.NVarChar(140), encrypt(bankAccountNo.toString()));
		request.input("addressLine1", sql.NVarChar(500), encrypt(addressLine1));
		request.input("city", sql.NVarChar(200), encrypt(city));
		request.input("province", sql.NVarChar(200), encrypt(province));
		request.input("governorate", sql.NVarChar(200), encrypt(governorate));
		request.input("country", sql.NVarChar(200), encrypt(country));
		request.input("gasTransCert", sql.NVarChar(500), encrypt(baseUrl + gasTransCertImgName));
		request.input("civilCerts", sql.NVarChar(500), encrypt(baseUrl + civilCertsImgName));
		request.input("applicationCreditForm", sql.NVarChar(500),
			encrypt(baseUrl + applicationCreditFormImgName));
		request.input("cr", sql.NVarChar(500), encrypt(baseUrl + crImgName));
		request.input("occiCert", sql.NVarChar(500), encrypt(baseUrl + occiCertImgName));
		request.input("sponsorId", sql.NVarChar(500), encrypt(baseUrl + sponsorIdImgName));
		request.input("guaranteeCheque", sql.NVarChar(500), encrypt(baseUrl + guaranteeChequeImgName));
		request.input("signDoc", sql.NVarChar(500), encrypt(baseUrl + signDocImgName));
		request.input("civilDefianceCert", sql.NVarChar(500), encrypt(baseUrl + civilDefianceCertImgName));
		request.input("lpgSaleApproval", sql.NVarChar(500), encrypt(baseUrl + lpgSaleApprovalImgName));

		if (addressLine2) {
			request.input("addressLine2", sql.NVarChar(500), encrypt(addressLine2));
		} else {
			request.input("addressLine2", sql.NVarChar(500), addressLine2);
		}

		var q = "insert into users(id, mobileNo, password, email, idNo, fName, lName, userType)" +
			"values(@id, @mobile, @pass, @email, @idNo, @fName, @lName, @userType);" +
			"insert into drivers values(@id, @plateCode, @plateNumber, @bankName, @bankBranch, " +
			"@bankAccountName, @bankAccountNo, @addressLine1, @addressLine2, @city, @province, " +
			"@governorate, @country, @gasTransCert, @civilCerts, @applicationCreditForm, " +
			"@cr, @occiCert, @sponsorId, @guaranteeCheque, @signDoc, @civilDefianceCert, @lpgSaleApproval)";

		await request.query(q);

		res.json({
			msg: "Driver registered successfully"
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log("Driver registered successfully\n");
	} catch (err) {
		var msg = "Error while creating user: " + err;

		res.json({
			error: msg
		});

		console.log(res.statusCode + " - " + res.statusMessage + "\n");
		console.log(err);
		console.log();
	}
});*/

app.get("/", async function(req, res) {
	res.send("mGas Web Service");
});

server.listen(process.env.PORT || 8080, function() {
	var host = server.address().address;
	var port = server.address().port;

	console.log("Listening on " + host + ":" + port + "\n");
});