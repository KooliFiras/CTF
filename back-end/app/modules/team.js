var mongoose = require ('mongoose')

var teamSchema = new mongoose.Schema({

    team_name:{type:String},
    creation_date:{type:Date},
    list_participant:[{type:mongoose.Schema.Types.ObjectId,
                        ref:'Participant'}],
    avtar:{type:Object},
    score:{type:Number},
    problem_solved:[{type:mongoose.Schema.Types.ObjectId,
                        ref:'Problem'}],
    problem_favorites:[{type:mongoose.Schema.Types.ObjectId,
                        ref:'Problem'}],
    notifications:[{type:mongoose.Schema.Types.ObjectId}],
    list_problems_added:[{type:mongoose.Schema.Types.ObjectId,
                         ref:'Problem'}]
})

module.exports=mongoose.model('Team',teamSchema)