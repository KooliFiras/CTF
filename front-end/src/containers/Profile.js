import React, { Component } from 'react';

export default class Profile extends Component {
  render() {
    return (
      <div className="container">
	<div className="row">
	 <div className="col-md-12">
      <div className="card">
            <ul className="nav nav-tabs" role="tablist">
                  <li role="presentation" className="active"><a href="#home" aria-controls="home" role="tab" data-toggle="tab">Profile</a></li>
                      <li role="presentation"><a href="#profile" aria-controls="profile" role="tab" data-toggle="tab">Notifications</a></li>
                            <li role="presentation"><a href="#messages" aria-controls="messages" role="tab" data-toggle="tab">Messages</a></li>
                                <li role="presentation"><a href="#settings" aria-controls="settings" role="tab" data-toggle="tab">Settings</a></li>
              </ul>


                                    <div className="tab-content">
                                        <div role="tabpanel" className="tab-pane active" id="home">
                                          <p> Here profile content </p>
                                        </div>
                                        <div role="tabpanel" className="tab-pane" id="profile">
                                          <p>here lits of notifications </p>
                                          </div>
                                        <div role="tabpanel" className="tab-pane" id="messages">
                                          <p> List pf messages </p>
                                         </div>
                                        <div role="tabpanel" className="tab-pane" id="settings">
                                           <p> settings here </p>
                                         </div>
                                    </div>
</div>
                                </div>
	</div>
</div>
    );
  }
}
