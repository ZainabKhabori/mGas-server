create database mGas;
use mGas;

create table locations
(
	id char(32),
	longitude varchar(140),
	latitude varchar(140),
	addressLine1 varchar(500),
	addressLine2 varchar(500),
	city varchar(200),
	province varchar(200),
	governorate varchar(200),
	country varchar(200),
	primary key(id)
);

create table users
(
	id char(32),
	mobileNo int,
	password char(60),
	email varchar(300),
	idNo varchar(120),
	fName varchar(140),
	lName varchar(140),
	displayPicThumb varbinary(MAX),
	displayPicUrl varchar(500),
	userType varchar(8),
	primary key(id),
	unique(mobileNo)
);

create table consumers
(
	userId char(32),
	gender varchar(100),
	dateOfBirth char(144),
	age varchar(106),
	mainLocationId char(32),
	mainLocationName varchar(40),
	primary key(userId),
	foreign key(userId) references users(id),
	foreign key(mainLocationId) references locations(id)
);

create table drivers
(
	userId char(32),
	plateCode varchar(108),
	plateNumber varchar(116),
	bankName varchar(160),
	bankBranch varchar(140),
	bankAccountName varchar(200),
	bankAccountNo varchar(140),
	addressLine1 varchar(500),
	addressLine2 varchar(500),
	city varchar(200),
	province varchar(200),
	governorate varchar(200),
	country varchar(200),
	gasTransCert varchar(500),
	civilCerts varchar(500),
	applicationCreditForm varchar(500),
	cr varchar(500),
	occiCert varchar(500),
	sponsorId varchar(500),
	guaranteeCheque varchar(500),
	signDoc varchar(500),
	civilDefianceCert varchar(500),
	lpgSaleApproval varchar(500),
	primary key(userId),
	foreign key(userId) references users(id)
);

create table bankCards
(
	id char(32),
	owner char(32),
	cardNo varchar(132),
	expDateMonth varchar(104),
	expDateYear varchar(108),
	cvv varchar(106),
	primary key(id),
	foreign key(owner) references consumers(userId)
);

create table consumerLocations
(
	consumerId char(32),
	locationId char(32),
	locationName varchar(40),
	primary key(consumerId, locationId),
	foreign key(consumerId) references consumers(userId),
	foreign key(locationId) references locations(id)
);

create table services
(
	id char(32),
	type varchar(200),
	cylinderSize varchar(110),
	charge varchar(114),
	dateModified char(144),
	primary key(id)
);

create table orders
(
	id char(32),
	consumerId char(32),
	driverId char(32),
	locationId char(32),
	orderDate char(144),
	deliveryOptionId char(32),
	totalCost varchar(112),
	status varchar(20),
	orderCode char(4),
	primary key(id),
	foreign key(consumerId) references consumers(userId),
	foreign key(driverId) references drivers(userId),
	foreign key(locationId) references locations(id),
	foreign key(deliveryOptionId) references services(id)
);

create table orderServices
(
	orderId char(32),
	serviceId char(32),
	quantity varchar(106),
	primary key(orderId, serviceId),
	foreign key(orderId) references orders(id)
);

create table deliveryIssues
(
	id char(32),
	driverId char(32),
	orderId char(32),
	dateReported datetime,
	issue varchar(500),
	primary key(id),
	foreign key(driverId) references drivers(userId),
	foreign key(orderId) references orders(id)
);

create table feedbacks
(
	id char(32),
	orderId char(32),
	author char(32),
	authorUserType varchar(8),
	message varchar(500),
	primary key(id),
	foreign key(orderId) references orders(id),
	foreign key(author) references users(id)
);

create table lotteries
(
	id char(32),
	startDate date,
	endDate date,
	winner char(32),
	winningCode char(116),
	primary key(id),
	foreign key(winner) references consumers(userId)
);

create table promotionCodes
(
	lotteryId char(32),
	serial int identity(1,1),
	code char(116),
	expDate char(144),
	used bit not null,
	owner char(32),
	primary key(code),
	foreign key(lotteryId) references lotteries(id),
	foreign key(owner) references consumers(userId)
);

alter table lotteries add foreign key(winningCode) references promotionCodes(code);

create table notifications
(
	id char(32),
	title varchar(30),
	text varchar(200),
	image varchar(200),
	scheduledTime datetime,
	type varchar(11),
	primary key(id)
);

create table interactiveNotifications
(
	notificationId char(32),
	correctChoice char(32),
	primary key(notificationId),
	foreign key(notificationId) references notifications(id)
);

create table interactiveNotifChoices
(
	id char(32),
	interactiveNotifId char(32),
	title varchar(20),
	description varchar(200),
	image varchar(200),
	selectionsNo int,
	primary key(id),
	unique(interactiveNotifId, title),
	foreign key(interactiveNotifId) references interactiveNotifications(notificationId)
);

alter table interactiveNotifications add foreign key(correctChoice) references interactiveNotifChoices(id);







select * from users;
select * from locations;
select * from consumers;
select * from consumerLocations;

delete from consumerLocations where locationId='ea8d1a5273fe858d8a5646be0c9a436f' and consumerId='8e2bbe293f25830bf4863590b461cbc5';
delete from consumers where userId='8e2bbe293f25830bf4863590b461cbc5';
delete from users where id='8e2bbe293f25830bf4863590b461cbc5';
delete from locations where id='ea8d1a5273fe858d8a5646be0c9a436f';

select * from users;
select * from drivers;

delete from drivers where userId='45c88b92c845d135b942d88d304d0264';
delete from users where id='45c88b92c845d135b942d88d304d0264';

select * from services;

delete from services where id='b1dfdbf170844f5b404d03e61f78e378';

select * from orders;
select * from orderServices;

delete from orderServices where orderId='00c28b19604dbf53fbc1550600fa201e' or orderId='53f8ab05be08dcb1e773db47e81c4474';
delete from orders where id='00c28b19604dbf53fbc1550600fa201e' or id='53f8ab05be08dcb1e773db47e81c4474';

update orders set orderCode='6528' where id='53ae773dad7d3343950028c565074273';

select * from feedbacks;
select * from deliveryIssues;

delete from feedbacks where id='8011e4c5a951f188714464486d6c9f28';

drop table deliveryIssues;
drop table orderServices;
drop table feedbacks;
drop table orders;
drop table services;

insert into lotteries(id, startDate) values('1a2b3c4d5e6ff6e5d4c3b2a111aa22bb', '2019-05-20T08:14:02.555Z');

select * from lotteries;

delete from lotteries where id='74e58a491a8f5cd3db61c5b7d95eefcd';

select * from lotteries where startDate <= '2019-05-21T04:14:48.845Z';

select * from bankCards;
select * from promotionCodes;

delete from promotionCodes where serial=1 or serial=2 or serial=3 or serial=4 or serial=5;
DBCC CHECKIDENT (promotionCodes, reseed, 0);