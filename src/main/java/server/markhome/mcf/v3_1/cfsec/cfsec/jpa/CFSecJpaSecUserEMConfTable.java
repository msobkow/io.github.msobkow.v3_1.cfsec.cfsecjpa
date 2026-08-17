
// Description: Java 25 DbIO implementation for SecUserEMConf.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.lang.reflect.*;
import java.net.*;
import java.rmi.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;

import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.jpa.CFSecJpaHooksSchema;

/*
 *	CFSecJpaSecUserEMConfTable database implementation for SecUserEMConf
 */
public class CFSecJpaSecUserEMConfTable implements ICFSecSecUserEMConfTable
{
	protected CFSecJpaSchema schema;


	public CFSecJpaSecUserEMConfTable(ICFSecSchema schema) {
		if( schema == null ) {
			throw new CFLibNullArgumentException(getClass(), "constructor", 1, "schema" );
		}
		if (schema instanceof CFSecJpaSchema) {
			this.schema = (CFSecJpaSchema)schema;
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "constructor", "schema", schema, "CFSecJpaSchema");
		}
	}

	protected boolean canCreateSecUserEMConf(String S_ProcName, ICFSecAuthorization Authorization) {
		if (Authorization == null) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization");
		}
		boolean permissionGranted = false;
		CFLibDbKeyHash256 authUserId = Authorization.getSecUserId();
		if ((!permissionGranted) && (authUserId == null || authUserId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization.getSecUserId()");
		}
		// Check for "system" user
		CFLibDbKeyHash256 systemId = ICFSecSchema.getSystemId();
		if ((!permissionGranted) && (systemId != null && !systemId.isNull() && systemId.equals(authUserId))) {
			permissionGranted = true;
		}
		else if ((!permissionGranted) && (systemId == null || systemId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "ICFSecSchema.getSystemId()");
		}
		if(!permissionGranted) {
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "createsecuseremconf");
		}
		return( permissionGranted );
	}

	protected boolean canReadSecUserEMConf(String S_ProcName, ICFSecAuthorization Authorization) {
		if (Authorization == null) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization");
		}
		boolean permissionGranted = false;
		CFLibDbKeyHash256 authUserId = Authorization.getSecUserId();
		if ((!permissionGranted) && (authUserId == null || authUserId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization.getSecUserId()");
		}
		// Check for "system" user
		CFLibDbKeyHash256 systemId = ICFSecSchema.getSystemId();
		if ((!permissionGranted) && (systemId != null && !systemId.isNull() && systemId.equals(authUserId))) {
			permissionGranted = true;
		}
		else if ((!permissionGranted) && (systemId == null || systemId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "ICFSecSchema.getSystemId()");
		}
		if(!permissionGranted) {
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "readsecuseremconf");
		}
		return( permissionGranted );
	}

	protected boolean canUpdateSecUserEMConf(String S_ProcName, ICFSecAuthorization Authorization) {
		if (Authorization == null) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization");
		}
		boolean permissionGranted = false;
		CFLibDbKeyHash256 authUserId = Authorization.getSecUserId();
		if ((!permissionGranted) && (authUserId == null || authUserId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization.getSecUserId()");
		}
		// Check for "system" user
		CFLibDbKeyHash256 systemId = ICFSecSchema.getSystemId();
		if ((!permissionGranted) && (systemId != null && !systemId.isNull() && systemId.equals(authUserId))) {
			permissionGranted = true;
		}
		else if ((!permissionGranted) && (systemId == null || systemId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "ICFSecSchema.getSystemId()");
		}
		if(!permissionGranted) {
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "updatesecuseremconf");
		}
		return( permissionGranted );
	}

	protected boolean canDeleteSecUserEMConf(String S_ProcName, ICFSecAuthorization Authorization) {
		if (Authorization == null) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization");
		}
		boolean permissionGranted = false;
		CFLibDbKeyHash256 authUserId = Authorization.getSecUserId();
		if ((!permissionGranted) && (authUserId == null || authUserId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization.getSecUserId()");
		}
		// Check for "system" user
		CFLibDbKeyHash256 systemId = ICFSecSchema.getSystemId();
		if ((!permissionGranted) && (systemId != null && !systemId.isNull() && systemId.equals(authUserId))) {
			permissionGranted = true;
		}
		else if ((!permissionGranted) && (systemId == null || systemId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "ICFSecSchema.getSystemId()");
		}
		if(!permissionGranted) {
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "deletesecuseremconf");
		}
		return( permissionGranted );
	}

	/**
	 *	Create the instance in the database, and update the specified record
	 *	with the assigned primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	rec	The instance interface to be created.
	 */
	@Override
	public ICFSecSecUserEMConf createSecUserEMConf( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConf rec )
	{
		final String S_ProcName = "createSecUserEMConf";
		boolean permissionGranted = canCreateSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "createsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "createSecUserEMConf", 1, "rec");
		}
		else if (rec instanceof CFSecJpaSecUserEMConf) {
			CFSecJpaSecUserEMConf jparec = (CFSecJpaSecUserEMConf)rec;
			jparec.setCreatedAt(LocalDateTime.now());
			jparec.setUpdatedAt(jparec.getCreatedAt());
			jparec.setCreatedByUserId(Authorization.getSecUserId());
			jparec.setUpdatedByUserId(Authorization.getSecUserId());
			CFSecJpaSecUserEMConf retval = schema.getJpaHooksSchema().getSecUserEMConfService().create(jparec);
		return(retval);
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "createSecUserEMConf", "rec", rec, "CFSecJpaSecUserEMConf");
		}
	}

	/**
	 *	Update the instance in the database, and update the specified record
	 *	with any calculated changes imposed by the associated stored procedure.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	rec	The instance interface to be updated
	 */
	@Override
	public ICFSecSecUserEMConf updateSecUserEMConf( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConf rec )
	{
		final String S_ProcName = "updateSecUserEMConf";
		boolean permissionGranted = canUpdateSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "updateSecUserEMConf", 1, "rec");
		}
		else if (rec instanceof CFSecJpaSecUserEMConf) {
			CFSecJpaSecUserEMConf jparec = (CFSecJpaSecUserEMConf)rec;
			jparec.setUpdatedAt(LocalDateTime.now());
			jparec.setUpdatedByUserId(Authorization.getSecUserId());
			CFSecJpaSecUserEMConf retval = schema.getJpaHooksSchema().getSecUserEMConfService().update(jparec);
		return(retval);
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "updateSecUserEMConf", "rec", rec, "CFSecJpaSecUserEMConf");
		}
	}

	/**
	 *	Delete the instance from the database.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	rec	The instance interface to be deleted.
	 */
	@Override
	public void deleteSecUserEMConf( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConf rec )
	{
		final String S_ProcName = "deleteSecUserEMConf";
		boolean permissionGranted = canDeleteSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			return;
		}
		if (rec instanceof CFSecJpaSecUserEMConf) {
			CFSecJpaSecUserEMConf jparec = (CFSecJpaSecUserEMConf)rec;
			schema.getJpaHooksSchema().getSecUserEMConfService().deleteByIdIdx(jparec.getPKey());
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "deleteSecUserEMConf", "rec", rec, "CFSecJpaSecUserEMConf");
		}

		throw new CFLibNotImplementedYetException(getClass(), "deleteSecUserEMConf");
	}

	/**
	 *	Delete the SecUserEMConf instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The primary key identifying the instance to be deleted.
	 */
	@Override
	public void deleteSecUserEMConfByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argKey )
	{
		final String S_ProcName = "deleteSecUserEMConfByIdIdx";
		boolean permissionGranted = canDeleteSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecUserEMConfService().deleteByIdIdx(argKey);
	}

	/**
	 *	Delete the SecUserEMConf instances identified by the key UUuid6Idx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EMConfirmationUuid6	The SecUserEMConf key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecUserEMConfByUUuid6Idx( ICFSecAuthorization Authorization,
		ICFLibUuid6 argEMConfirmationUuid6 )
	{
		final String S_ProcName = "deleteSecUserEMConfByUUuid6Idx";
		boolean permissionGranted = canDeleteSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecUserEMConfService().deleteByUUuid6Idx(argEMConfirmationUuid6);
	}


	/**
	 *	Delete the SecUserEMConf instances identified by the key UUuid6Idx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecUserEMConfByUUuid6Idx( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConfByUUuid6IdxKey argKey )
	{
		final String S_ProcName = "deleteSecUserEMConfByUUuid6Idx";
		boolean permissionGranted = canDeleteSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecUserEMConfService().deleteByUUuid6Idx(argKey.getRequiredEMConfirmationUuid6());
	}

	/**
	 *	Delete the SecUserEMConf instances identified by the key ConfEMAddrIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ConfirmEMailAddr	The SecUserEMConf key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecUserEMConfByConfEMAddrIdx( ICFSecAuthorization Authorization,
		String argConfirmEMailAddr )
	{
		final String S_ProcName = "deleteSecUserEMConfByConfEMAddrIdx";
		boolean permissionGranted = canDeleteSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecUserEMConfService().deleteByConfEMAddrIdx(argConfirmEMailAddr);
	}


	/**
	 *	Delete the SecUserEMConf instances identified by the key ConfEMAddrIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecUserEMConfByConfEMAddrIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConfByConfEMAddrIdxKey argKey )
	{
		final String S_ProcName = "deleteSecUserEMConfByConfEMAddrIdx";
		boolean permissionGranted = canDeleteSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecUserEMConfService().deleteByConfEMAddrIdx(argKey.getRequiredConfirmEMailAddr());
	}

	/**
	 *	Delete the SecUserEMConf instances identified by the key SentStampIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EMailSentStamp	The SecUserEMConf key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecUserEMConfBySentStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime argEMailSentStamp )
	{
		final String S_ProcName = "deleteSecUserEMConfBySentStampIdx";
		boolean permissionGranted = canDeleteSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecUserEMConfService().deleteBySentStampIdx(argEMailSentStamp);
	}


	/**
	 *	Delete the SecUserEMConf instances identified by the key SentStampIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecUserEMConfBySentStampIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConfBySentStampIdxKey argKey )
	{
		final String S_ProcName = "deleteSecUserEMConfBySentStampIdx";
		boolean permissionGranted = canDeleteSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecUserEMConfService().deleteBySentStampIdx(argKey.getRequiredEMailSentStamp());
	}

	/**
	 *	Delete the SecUserEMConf instances identified by the key NewAcctIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	NewAccount	The SecUserEMConf key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecUserEMConfByNewAcctIdx( ICFSecAuthorization Authorization,
		boolean argNewAccount )
	{
		final String S_ProcName = "deleteSecUserEMConfByNewAcctIdx";
		boolean permissionGranted = canDeleteSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecUserEMConfService().deleteByNewAcctIdx(argNewAccount);
	}


	/**
	 *	Delete the SecUserEMConf instances identified by the key NewAcctIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecUserEMConfByNewAcctIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConfByNewAcctIdxKey argKey )
	{
		final String S_ProcName = "deleteSecUserEMConfByNewAcctIdx";
		boolean permissionGranted = canDeleteSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecUserEMConfService().deleteByNewAcctIdx(argKey.getRequiredNewAccount());
	}


	/**
	 *	Read the derived SecUserEMConf record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecUserEMConf instance to be read.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecUserEMConf readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "readDerived";
		boolean permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecUserEMConf retval = schema.getJpaHooksSchema().getSecUserEMConfService().find(PKey);
		return(retval);
	}

	/**
	 *	Lock the derived SecUserEMConf record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecUserEMConf instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecUserEMConf lockDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "lockDerived";
		boolean permissionGranted = canUpdateSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecUserEMConf retval = schema.getJpaHooksSchema().getSecUserEMConfService().lockByIdIdx(PKey);
		return(retval);
	}

	/**
	 *	Read all SecUserEMConf instances.
	 *
	 *	@param	Authorization	The session authorization information.	
	 *
	 *	@return An array of derived record instances, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecUserEMConf[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllDerived";
		boolean permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		List<CFSecJpaSecUserEMConf> retlist = schema.getJpaHooksSchema().getSecUserEMConfService().findAll();
		ICFSecSecUserEMConf[] retset = new ICFSecSecUserEMConf[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecUserEMConf cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the derived SecUserEMConf record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecUserEMConf readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecUserId )
	{
		final String S_ProcName = "readDerivedByIdIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		ICFSecSecUserEMConf retval = schema.getJpaHooksSchema().getSecUserEMConfService().find(argSecUserId);
		return(retval);
	}

	/**
	 *	Read the derived SecUserEMConf record instance identified by the unique key UUuid6Idx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EMConfirmationUuid6	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecUserEMConf readDerivedByUUuid6Idx( ICFSecAuthorization Authorization,
		ICFLibUuid6 argEMConfirmationUuid6 )
	{
		final String S_ProcName = "readDerivedByUUuid6Idx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		ICFSecSecUserEMConf retval = schema.getJpaHooksSchema().getSecUserEMConfService().findByUUuid6Idx(argEMConfirmationUuid6);
		return(retval);
	}

	/**
	 *	Read an array of the derived SecUserEMConf record instances identified by the duplicate key ConfEMAddrIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ConfirmEMailAddr	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecUserEMConf[] readDerivedByConfEMAddrIdx( ICFSecAuthorization Authorization,
		String argConfirmEMailAddr )
	{
		final String S_ProcName = "readDerivedByConfEMAddrIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaSecUserEMConf> retlist = schema.getJpaHooksSchema().getSecUserEMConfService().findByConfEMAddrIdx(argConfirmEMailAddr);
		ICFSecSecUserEMConf[] retset = new ICFSecSecUserEMConf[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecUserEMConf cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read an array of the derived SecUserEMConf record instances identified by the duplicate key SentStampIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EMailSentStamp	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecUserEMConf[] readDerivedBySentStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime argEMailSentStamp )
	{
		final String S_ProcName = "readDerivedBySentStampIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaSecUserEMConf> retlist = schema.getJpaHooksSchema().getSecUserEMConfService().findBySentStampIdx(argEMailSentStamp);
		ICFSecSecUserEMConf[] retset = new ICFSecSecUserEMConf[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecUserEMConf cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read an array of the derived SecUserEMConf record instances identified by the duplicate key NewAcctIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	NewAccount	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecUserEMConf[] readDerivedByNewAcctIdx( ICFSecAuthorization Authorization,
		boolean argNewAccount )
	{
		final String S_ProcName = "readDerivedByNewAcctIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaSecUserEMConf> retlist = schema.getJpaHooksSchema().getSecUserEMConfService().findByNewAcctIdx(argNewAccount);
		ICFSecSecUserEMConf[] retset = new ICFSecSecUserEMConf[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecUserEMConf cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the specific SecUserEMConf record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecUserEMConf instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "readRec";
		boolean permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRec");
	}

	/**
	 *	Lock the specific SecUserEMConf record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecUserEMConf instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf lockRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		boolean permissionGranted = canUpdateSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "lockRec");
	}

	/**
	 *	Read all the specific SecUserEMConf record instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecUserEMConf instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecUserEMConf[] readAllRec( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllRec";
		boolean permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readAllRec");
	}


	/**
	 *	Read a page of all the specific SecUserEMConf record instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecUserEMConf instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecUserEMConf[] pageAllRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageAllRec";
		boolean permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "pageAllRec");
	}

	/**
	 *	Read the specific SecUserEMConf record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecUserId )
	{
		final String S_ProcName = "readRecByIdIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByIdIdx");
	}

	/**
	 *	Read the specific SecUserEMConf record instance identified by the unique key UUuid6Idx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EMConfirmationUuid6	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf readRecByUUuid6Idx( ICFSecAuthorization Authorization,
		ICFLibUuid6 argEMConfirmationUuid6 )
	{
		final String S_ProcName = "readRecByUUuid6Idx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByUUuid6Idx");
	}

	/**
	 *	Read an array of the specific SecUserEMConf record instances identified by the duplicate key ConfEMAddrIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ConfirmEMailAddr	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf[] readRecByConfEMAddrIdx( ICFSecAuthorization Authorization,
		String argConfirmEMailAddr )
	{
		final String S_ProcName = "readRecByConfEMAddrIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByConfEMAddrIdx");
	}

	/**
	 *	Read an array of the specific SecUserEMConf record instances identified by the duplicate key SentStampIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EMailSentStamp	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf[] readRecBySentStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime argEMailSentStamp )
	{
		final String S_ProcName = "readRecBySentStampIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecBySentStampIdx");
	}

	/**
	 *	Read an array of the specific SecUserEMConf record instances identified by the duplicate key NewAcctIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	NewAccount	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf[] readRecByNewAcctIdx( ICFSecAuthorization Authorization,
		boolean argNewAccount )
	{
		final String S_ProcName = "readRecByNewAcctIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByNewAcctIdx");
	}

	/**
	 *	Read a page array of the specific SecUserEMConf record instances identified by the duplicate key ConfEMAddrIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ConfirmEMailAddr	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf[] pageRecByConfEMAddrIdx( ICFSecAuthorization Authorization,
		String argConfirmEMailAddr,
		ICFLibKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecByConfEMAddrIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "pageRecByConfEMAddrIdx");
	}

	/**
	 *	Read a page array of the specific SecUserEMConf record instances identified by the duplicate key SentStampIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EMailSentStamp	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf[] pageRecBySentStampIdx( ICFSecAuthorization Authorization,
		LocalDateTime argEMailSentStamp,
		ICFLibKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecBySentStampIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "pageRecBySentStampIdx");
	}

	/**
	 *	Read a page array of the specific SecUserEMConf record instances identified by the duplicate key NewAcctIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	NewAccount	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf[] pageRecByNewAcctIdx( ICFSecAuthorization Authorization,
		boolean argNewAccount,
		ICFLibKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecByNewAcctIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecUserEMConf(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecuseremconf", ICFSecSchema.SCHEMA_NAME, ICFSecSecUserEMConfTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "pageRecByNewAcctIdx");
	}
}
