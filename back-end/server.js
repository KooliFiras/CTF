var express = require('express')
var bodyParser = require('body-parser')
var morgan = require('morgan')
var mongoose = require('mongoose')
var passport	= require('passport');
var jwt = require ('jwt-simple')

// config file
var config = require('./config/config')


mongoose.connect(config.database, function (error) {
    if (error) {
        console.log(error)
    }
    else {
        console.log('You are connected to DB')
    }
})

var app = express()

app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

var api = require('./app/routes/api')(app, express)


/* **************** middlewares ********* */
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: false}))
//app.use(express.static(__dirname + '/public'))
app.use(morgan('dev'))
app.use('/api', api)
app.use(passport.initialize());



app.get('/', function(req, res) {
    res.send('Hello! The API is at http://localhost:' + config.port + '/api');
});



app.listen(config.port, function (error) {
    if (error) {
        console.log(error)
    }
    else {
        console.log('You are listening on port' + config.port)
    }
})

