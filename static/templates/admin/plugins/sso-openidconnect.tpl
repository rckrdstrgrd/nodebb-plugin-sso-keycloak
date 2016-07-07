<form role="form" class="sso-keycloak-settings">
	<div class="row">
		<div class="col-sm-2 col-xs-12 settings-header">General</div>
		<div class="col-sm-10 col-xs-12">
			<div class="form-group">
  				<label for="comment">Keycloak OIDC JSON</label>
  				<textarea class="form-control" rows="8" id="keycloak-config" name="keycloak-config" title="Keycloak OIDC JSON"></textarea>
			</div>	
			<div class="form-group">
				<label for="callback-url">Callback URL</label>
				<input type="text" id="callback-url" name="callback-url" title="Callback URL" class="form-control" >
			</div>
			<div class="form-group">
				<label for="callback-url">Admin URL</label>
				<input type="text" id="admin-url" name="admin-url" title="Admin URL" class="form-control" >
			</div>
			
		</div>
	</div>
</form>

<button id="save" class="floating-button mdl-button mdl-js-button mdl-button--fab mdl-js-ripple-effect mdl-button--colored">
	<i class="material-icons">save</i>
</button>
