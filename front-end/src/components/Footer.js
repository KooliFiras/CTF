import React, { Component } from 'react';

export default class Footer extends Component {


  constructor(props) {
    super(props);
    this.state = {

    };
  }



  componentWillMount()
  {
    //********here we will GET DATA from redux to chekc if user authenticated o
    //********not
  }




  render() {
    return (
        <nav className="navbar navbar-default navbar-fixed-bottom">
      <div className="container">


<div className="row">

<div className="col-md-4">
<p>contact us  : ctf@gmail.com <i className="fa fa-envelope" aria-hidden="true"></i> </p>
<p>Join Us  :    <a href="https://slack.com/" class="btn btn-white btn-default active">in slack <i className="fa fa-slack" aria-hidden="true"></i></a> </p>
</div>


<div className="col-md-4">
  <p>built by <i className="fa fa-heart" aria-hidden="true"></i>  with ahmed && firas</p>
</div>


<div className="col-md-4">
  <ul>
<li>
   <a href="https://twitter.com/" class="btn btn-white btn-default active">

      <i className="fa fa-twitter" aria-hidden="true"></i>
    Twitter

  </a>
  </li>
<li>
   <a href="https://plus.google.com/u/3/discover" class="btn btn-white btn-default active">
<i className="fa fa-google-plus-square" aria-hidden="true"></i>
 oogle+
 </a>
</li>
<li>
     <a href="https://www.facebook.com/" class="btn btn-white btn-default active">
   <i className="fa fa-facebook" aria-hidden="true"></i>
      acebook
    </a>
    </li>
  </ul>
</div>


</div>




      <hr />
  </div>
</nav>
    );
  }
}
