var mongoose = require('mongoose');
var passport = require('passport');
var express = require('express');
var jwt = require('jsonwebtoken');
var bcrypt = require('bcrypt-nodejs');
var request = require('request');


var Participant  = require ('../modules/participant')
var Problem= require ('../modules/problem')
var Contest= require ('../modules/contest')
var Team= require ('../modules/team')


var config      = require('../../config/config'); // get db config file

require('../../config/passport')(passport);


module.exports=function(app,express){

    var api = express.Router()

    api.post('/user/signup',function(req,res){

        if (!req.body.username ) {
            res.json({success: false, msg: 'Please pass a username'});
        } else if ( !req.body.email ){
            res.json({success: false, msg: 'Please pass an email'});
        }else if ( !req.body.password ){
            res.json({success: false, msg: 'Please pass a password'});
        } else {
                    var participant = new Participant({
                        username: req.body.username,
                        email: req.body.email,
                        password: req.body.password
                    });
                    // save the user
                    participant.save(function(err,user) {
                        if (err) {
                            return res.json({success: false, msg:'email already existing'});
                        }
                        var token = jwt.sign(user, config.secret);
                        res.json({success: true, msg: 'Successfully  created new participant.', token: token});
                    });
                }
            })


    api.post('/user/login', function(req, res) {
        Participant.findOne({
            username: req.body.username
        }, function(err, user) {
            if (err) throw err;

            if (!user) {
                res.status(401).send({success: false, msg: 'Authentication failed. User not found.'});
            } else {
                // check if password matches
                user.comparePassword(req.body.password, function (err, isMatch) {
                    if (isMatch && !err) {
                        // if user is found and password is right create a token
                        var token = jwt.sign(user, config.secret);
                        // return the information including token as JSON
                        res.json({success: true, token: token});
                    } else {
                        res.status(401).json({success: false, msg: 'Authentication failed. Wrong password.'});
                    }
                });
            }
        });
    });


    api.get('/user/auth/github',
        passport.authenticate('github', { scope: [ 'user:email' ] }));


    api.get('/user/auth/github/callback',function(req, res,next ) {

       passport.authenticate('github',function (err,user,info) {
            console.log(err, user,info);
             res.json(true)

            }
        )(req,res,next)


        //return res.status(200).send({success: true, msg: 'Ok.'});
    })


    api.get('/user/profile', passport.authenticate('jwt', { session: false}), function(req, res) {
            var token = getToken(req.headers);
            if (token) {
                    res.json(req.user);
                } else {
                return res.status(403).json({success: false, msg: 'Unauthorized.'});
            }
    });


    api.patch('/user/profile',passport.authenticate('jwt', { session: false}), function(req, res) {

        var token = getToken(req.headers);
        if (token) {

            Participant.findOne({
                _id: req.user._id
            }, function (err, user) {

                if (err) {
                    res.status(401).json({success: false, msg: err});
                }
                else if (!user ) {
                    res.status(401).json({success: false, msg: ' User not found.'});
                }
                else {
                    if (req.body.username){
                        Participant.findOne({username:req.body.username},function (err1,user1){

                            if (err1) {
                                res.status(401).json({success: false, msg: err1});
                            }

                            if (!user1){

                                user.username = req.body.username;

                                if  (req.body.firstname){
                                    user.firstname = req.body.firstname;
                                }

                                if (req.body.lastname){
                                    user.lastname = req.body.lastname;
                                }

                                if (req.body.school ){
                                    user.school = req.body.school;
                                }

                                if (req.body.experience  ){
                                    user.experience= req.body.experience;
                                }

                                if (req.body.country  ){
                                    user.country= req.body.country;
                                }

                                Participant.update({_id: req.user._id}, user, function(err2, raw) {
                                    if (err2) {
                                        res.json({success: false, msg: err2});
                                    }
                                    res.status(200).json({success: true, msg: 'profile successfully updated',user:user});
                                });
                            }
                            else {
                                if (req.body.username== req.user.username){

                                    if  (req.body.firstname){
                                        user.firstname = req.body.firstname;
                                    }

                                    if (req.body.lastname){
                                        user.lastname = req.body.lastname;
                                    }

                                    if (req.body.school ){
                                        user.school = req.body.school;
                                    }

                                    if (req.body.experience  ){
                                        user.experience= req.body.experience;
                                    }

                                    if (req.body.country  ){
                                        user.country= req.body.country;
                                    }

                                    Participant.update({_id: req.user._id}, user, function(err2, raw) {
                                        if (err2) {
                                            res.json({success: false, msg: err2});
                                        }
                                        res.status(200).json({success: true, msg: 'profile successfully updated',user:user});
                                    });

                                }else{
                                    res.status(401).json({success: false, msg: 'username already existing'});
                                }

                            }

                        })

                    }

                }
            });



        }
        else {
            return res.status(403).send({success: false, msg: 'Unauthorized.'});
             }
        })


    api.patch('/user/password/change', passport.authenticate('jwt', { session: false}), function(req, res) {
        var token = getToken(req.headers);

        if (token) {

            Participant.findOne({_id: req.user._id},function (err, user) {

                if (err) {
                    res.status(401).json({success: false, msg: err});
                }
                else if (!user) {
                    res.status(401).json({success: false, msg: ' User not found.'});
                }
                else {

                    if (!req.body.currentPassword){
                        res.status(401).json({success: false, msg: ' Please pass  the current password'});
                    }else if(!req.body.password1){
                        res.status(401).json({success: false, msg: ' Please pass the new password'});
                    }else if(!req.body.password2){
                        res.status(401).json({success: false, msg: ' Please pass the check password '});
                    }
                    else if (req.body.password1 != req.body.password2){
                        res.status(401).json({success: false, msg: ' the passwords don\'t match'});
                    }
                    else {


                            // check if password matches
                            user.comparePassword(req.body.currentPassword, function (err1, isMatch) {
                                if (isMatch && !err1) {
                                    // if user is found and password is right create a token


                                    bcrypt.genSalt(10, function (err2, salt) {
                                        if (err2) {
                                            res.status(401).json({success: false, msg: err2});
                                        }

                                        bcrypt.hash(req.body.password1, salt, null, function (err3, hash) {

                                            if (err3) {
                                                res.status(401).json({success: false, msg: err3});
                                            }
                                            user.password = hash;

                                            Participant.update({_id: req.user._id}, user, function (err4, raw) {
                                                if (err4) {
                                                    res.json({success: false, msg: err4});
                                                }
                                                res.status(200).json({
                                                    success: true,
                                                    msg: 'profile successfully updated',
                                                    user: user
                                                });
                                            })

                                        });
                                    });
                                } else {
                                    res.status(401).json({
                                        success: false,
                                        msg: 'your  current password is wrong try again '
                                    });
                                }
                            })
                    }
                }
            })

        } else {
            return res.status(403).send({success: false, msg: 'Unauthorized.'});
        }
    });


    api.get('/user/all', passport.authenticate('jwt', { session: false}), function(req, res) {
        var token = getToken(req.headers);
        if (token) {
            Participant.find({},function (err, user) {

                if (err) {
                    res.status(401).json({success: false, msg: err});
                }
                else if (!user) {
                    res.status(401).json({success: false, msg: ' User not found.'});
                }
                else {
                    res.json({success: true, users: user});
                }
            })

        } else {
            return res.status(403).json({success: false, msg: 'Unauthorized.'});
        }
    });


    api.post('/contest/create',passport.authenticate('jwt', { session: false}), function(req, res) {
        var token = getToken(req.headers);
        if (token) {

            if (!req.body.title) {
                res.json({success: false, msg: 'Please pass a title'});
            }
            else if ( !req.body.description){
                res.json({success: false, msg: 'Please pass a description '});
            }else if ( !req.body.startTime){
                res.json({success: false, msg: 'Please pass a start time '});
            }else if (!req.body.endTime){
                res.json({success: false, msg: 'Please pass an end time '});
            } else if (!req.body.organisationType){
                res.json({success: false, msg: 'Please pass an organization type '});
            }else if (!req.body.organizationName){
                res.json({success: false, msg: 'Please pass an organization name '});
            }else if (req.body.startTime >= req.body.endTime ){
                res.json({success: false, msg: 'End time cannot be before Start Time '});
            } else {
                Contest.findOne({title:req.body.title},function(err,contest){
                    if (err){
                        res.status(403).json({success: false, msg: err});
                    }
                    if (contest){
                        res.status(403).json({success: false, msg: 'Contest title already existing'});
                    }else{

                        var new_contest = new Contest({
                            title: req.body.title,
                            description: req.body.description,
                            creation_date: new Date(),
                            start_date: req.body.startTime,
                            end_date: req.body.endTime,
                            organization_type: req.body.organisationType,
                            organization_name: req.body.organizationName,
                            moderators: [req.user.username]
                        });

                        new_contest.save(function(err1,contest1) {

                            if (err1) {
                                return res.json({success: false, msg: err1});
                            }
                            if(!contest1){
                                res.status(401).json({success: false, msg: 'failed to create the contest'});
                            }
                            res.json({success: true, msg: 'Successfully  created new contest.', contest: contest1});
                        });
                    }

                })

            }


        } else {
            return res.status(403).send({success: false, msg: 'Unauthorized.'});
        }
        })


    api.get('/contest/opened/all',passport.authenticate('jwt', { session: false}), function(req, res) {
            var token = getToken(req.headers);
            if (token) {
                var time = new Date();
                Contest.find({start_date:{$lt:time}, end_date:{$gt: time}},function(err,contest){

                    if (err){
                        return res.status(403).json({success: false, msg:err});
                    }else{
                        res.json({success: true, contests:contest})
                    }

                })

            } else {
                return res.status(403).json({success: false, msg: 'Unauthorized.'});
            }
        })


    api.get('/contest/closed/all',passport.authenticate('jwt', { session: false}), function(req, res) {
            var token = getToken(req.headers);
            if (token) {
                var time = new Date();
                Contest.find({ end_date:{$lt: time}},function(err,contest){

                    if (err){
                        return res.status(403).json({success: false, msg:err});
                    }else{
                        res.json({success: true, contests:contest})
                    }

                })

            } else {
                return res.status(403).json({success: false, msg: 'Unauthorized.'});
            }
        })


    api.patch('/contest/signup',passport.authenticate('jwt', { session: false}), function(req, res){

        var token = getToken(req.headers);

        if(token){

            Contest.findOne({_id:req.body.id},function(err,contest){

                if(err){
                    return res.status(403).json({success:false, msg:err})
                }
                if(!contest){
                    return res.status(403).json({success:false, msg:"No contest found!!"})
                }else{
                    contest.list_participant=[req.user.username];
                    Contest.update({_id:req.body.id},contest,function(err2,contest2){

                        if(err2){
                            return res.status(403).json({success:false, msg:err2})
                        }

                        if(!contest2){
                            return res.status(403).json({success:false, msg:"Signing up to the Contest fails"})
                        }else{
                            return res.status(403).json({success:true, msg:"Successfully signed up "})
                        }

                    })
                }
            })

        }else{
            return res.status(403).json({success:false, msg:"Unauthorized!!"})
        }


    })


    api.patch('/contest/challenge/add',passport.authenticate('jwt',{session:false}),function(req,res){

        var token= getToken(req.headers);
        if (token){

            if (!req.body.title){
                return res.status(403).json({success: false, msg: 'Please pass a challenge\'s title'});
            }
            if (!req.body.maxScore){
                return res.status(403).json({success: false, msg: 'Please pass a challenge\'s title'});
            }
            else{

                Problem.find({title: req.body.title},function(err,problem){

                    if (err){
                        return res.status(403).json({success: false, msg: err});
                    }
                    if (problem){
                        if (req.body.maxScore>0){

                            Contest.find({_id:req.body.id},function(err1,contest){

                                if (err1){
                                    return res.status(403).json({success: false, msg: err1});
                                }
                                if(contest){

                                    contest.list_of_problems=[
                                        {
                                            title :req.body.title,
                                            score: req.body.maxScore
                                        }
                                    ]

                                    Contest.update({_id: req.body.id},contest,function(err2,contest2){

                                        if (err2){
                                            return res.status(403).json({success: false, msg: err2});
                                        }

                                        if (!contest2){
                                            return res.status(403).json({success: false, msg: 'the challenge hasn\'t been added to the contest'});
                                        } else {
                                            return res.status(403).json({success: true, msg: 'the challenge has been added successfully to the contest', contest:contest2});
                                        }
                                    })
                                }
                            })
                        }
                    }
                })
            }




        }else{
            return res.status(403).json({success:false,msg:'Unauthorized.'})
        }


    })


    api.post('/challenge/create',passport.authenticate('jwt', { session: false}), function(req, res){
            var token = getToken(req.headers);
            if (token) {

                if (!req.body.title) {
                    res.json({success: false, msg: 'Please pass a title'});
                }
                else if ( !req.body.description){
                    res.json({success: false, msg: 'Please pass a description '});
                }else if ( !req.body.problemStatement){
                    res.json({success: false, msg: 'Please pass a Problem Statement '});
                }else if (!req.body.inputFormat){
                    res.json({success: false, msg: 'Please pass an Input Format '});
                } else if (!req.body.constraints){
                    res.json({success: false, msg: 'Please pass constraints '});
                }else if (!req.body.outputFormat){
                    res.json({success: false, msg: 'Please pass an output Format '});
                }else if (!req.body.tags){
                    res.json({success: false, msg: 'Please pass tags '});
                } else {
                    Problem.findOne({title:req.body.title},function(err,problem){
                        if (err){
                            res.status(403).json({success: false, msg: err});
                        }
                        if (problem){
                            res.status(403).json({success: false, msg: 'challenge\'s title already existing'});
                        }else{

                            var new_problem = new Problem({
                                title: req.body.title,
                                description: req.body.description,
                                problem_statement: req.body.problemStatement,
                                input_format: req.body.inputFormat,
                                constraints: req.body.constraints,
                                output_format: req.body.outputFormat,
                                tags: req.body.tags,
                                moderators: [req.user.username],
                                creation_date: new Date(),

                            });

                            new_problem.save(function(err1,problem1) {

                                if (err1) {
                                    return res.json({success: false, msg: err1});
                                }
                                if(!problem1){
                                    res.status(401).json({success: false, msg: 'failed to create the challenge'});
                                }
                                res.json({success: true, msg: 'Successfully  created new challenge.', challenge: problem1});
                            });
                        }

                    })

                }


            } else {
                return res.status(403).send({success: false, msg: 'Unauthorized.'});
            }
        })


    api.post('/challenge/details',passport.authenticate('jwt', { session: false}), function(req, res) {
            var token = getToken(req.headers);
            if (token) {

                if (!req.body.id) {
                    return res.status(403).send({success: false, msg: 'Unauthorized.'});
                }
                 else {
                    Problem.findOne({_id:req.body.id},function(err,problem){
                        if (err){
                            res.status(403).json({success: false, msg: err});
                        }
                        if (!problem){
                            res.status(403).json({success: false, msg: 'no challenge found '});
                        }else{
                            res.json({success: true,  challenge: problem});
                        }
                    })
                }

            } else {
                return res.status(403).send({success: false, msg: 'Unauthorized.'});
            }
        })


    api.patch('/challenge/update',passport.authenticate('jwt', { session: false}), function(req, res){

        var token = getToken(req.headers);

        if (token){

            if (!req.body.id) {
                return res.status(403).send({success: false, msg: 'Unauthorized.'});
            }else {

                Problem.findOne({_id: req.body.id}, function (err, problem) {

                    if (err) {
                        return res.status(403).send({success: false, msg: err});
                    }
                    if (!problem) {
                        return res.status(403).send({success: false, msg: 'No problem found'});
                    } else {

                        found =problem.moderators.includes(req.user.username)

                            if (found){

                                problem.language = req.body.language;
                                problem.challenge_difficulty = req.body.challengeDifficulty;
                                if (req.body.title) {

                                    Problem.findOne({title: req.body.title}, function (err1, problem1) {

                                        if (err1) {
                                            return res.status(403).send({success: false, msg: err1});
                                        }
                                        if (!problem1) {
                                            problem.title = req.body.title;

                                            if (!req.body.description) {
                                                problem.description = req.body.description;
                                            }

                                            if (!req.body.problemStatement) {
                                                problem.problem_statement = req.body.problemStatement;
                                            }

                                            if (!req.body.inputFormat) {
                                                problem.input_format = req.body.inputFormat;
                                            }

                                            if (!req.body.constraints) {
                                                problem.constraints = req.body.constraints;
                                            }

                                            if (!req.body.outputFormat) {
                                                problem.output_format = req.body.outputFormat;
                                            }

                                            if (!req.body.tags) {
                                                problem.output_format = req.body.tags;
                                            }

                                            Problem.update({_id: req.body.id}, problem, function (err2, problem2) {

                                                if (err2) {
                                                    return res.status(403).json({success: false, msg: err2});
                                                }
                                                if (!problem2) {
                                                    return res.status(403).json({success: false, msg: 'problem updating fails'});
                                                } else {

                                                    return res.status(403).json({
                                                        success: true,
                                                        msg: 'Successful challenge update ',
                                                        challenge: problem2
                                                    });
                                                }
                                            })

                                        } else {
                                            return res.status(403).send({success: false, msg: 'challenge\'s title exists'});
                                        }
                                    })
                                }

                            }else{
                                return res.status(403).json({success: false, msg: 'this challenge is owned by someone else and cannot be modified'});
                            }

                    }
                })
            }

        }else{
            return res.status(403).send({success: false, msg: 'Unauthorized.'});
        }

    })


    api.patch('/challenge/moderators/add',passport.authenticate('jwt',{session:false}), function (req,res){

        var token = getToken(req.headers);

        if (token) {

            if (!req.body.id) {
                return res.status(403).send({success: false, msg: 'Unauthorized.'});
            } else {

                Problem.findOne({_id: req.body.id}, function (err, problem) {

                    if (err) {
                        return res.status(403).send({success: false, msg: err});
                    }

                    if (!problem) {
                        return res.status(403).send({success: false, msg: 'Unauthorized.'});
                    } else {

                       found= problem.moderators.includes(req.user.username)

                            if (found) {

                                if (!req.body.username) {
                                    return res.status(403).send({
                                        success: false,
                                        msg: 'Please pass the moderator \'s name '
                                    });
                                } else {

                                    Participant.findOne({username: req.body.username}, function (err1, user) {

                                        if (err1) {
                                            return res.status(403).send({success: false, msg: err1});
                                        }
                                        if (!user) {

                                            return res.status(403).send({success: false, msg: 'No user found '});

                                        } else {

                                            found2= problem.moderators.includes(req.user.username)

                                            if(!found2){

                                                problem.moderators.push(req.body.username)


                                                Problem.update({_id: req.body.id}, problem, function (err2, problem2) {

                                                    if (err2) {
                                                        return res.status(403).json({success: false, msg: err2});
                                                    }

                                                    if (!problem2) {
                                                        return res.status(403).json({
                                                            success: false,
                                                            msg: 'problem updating fails'
                                                        });
                                                    } else {

                                                        return res.status(200).json({
                                                            success: true,
                                                            msg: 'Successful moderator adding ',
                                                            challenge: problem2
                                                        });
                                                    }
                                                })

                                            }else{
                                                return res.status(403).send({success: false, msg: 'Moderator already existing!'});
                                            }
                                        }
                                    })
                                }
                            }else{
                                return res.status(403).send({success: false, msg: 'this challenge is owned by someone else and cannot be modified.'});
                            }

                    }
                })
            }
        }
        else{
            return res.status(403).send({success: false, msg: 'Unauthorized.'});
        }

    })


    api.get('/contest/filter/:lang',passport.authenticate('jwt', { session: false}), function(req, res){

        var token = getToken(req.headers);
        if (token){
            var result =[];

            Problem.find({},function(err,problems){

                if (err){
                    return res.status(403).json({success:false, msg:err})
                }
                if (problems) {

                    problems.forEach(function(problem){

                      found=  problem.language.includes(req.params.lang)
                        if (found){
                          result.push(problem)
                        }

                    })

                }
            })

            return res.json({success:true, msg:result})

        }else{
            return res.status(403).json({success:false, msg:"Unauthorized!!"})
        }

    })


    api.get('/supportedLanguages',passport.authenticate('jwt',{session:false}),function(req,res){

        var token = getToken(req.headers);

        if (token) {

            request.get('http://api.hackerrank.com/checker/languages.json', function(error, response, body) {

                if(error){
                    return res.status(403).send({success: false, msg: error});
                }else{
                    return res.status(200).send({success: true, msg: body});

                }
            })

        }else{
            return res.status(403).send({success: false, msg: 'Unauthorized.'});
        }
    })





    getToken = function (headers) {
        if (headers && headers.authorization) {
            var parted = headers.authorization.split(' ');
            if (parted.length === 2) {
                return parted[1];
            } else {
                return null;
            }
        } else {
            return null;
        }
    };

return api
}