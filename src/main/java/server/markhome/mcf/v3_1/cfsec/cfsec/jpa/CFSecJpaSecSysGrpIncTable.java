
// Description: Java 25 DbIO implementation for SecSysGrpInc.

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
 *	CFSecJpaSecSysGrpIncTable database implementation for SecSysGrpInc
 */
public class CFSecJpaSecSysGrpIncTable implements ICFSecSecSysGrpIncTable
{
	protected CFSecJpaSchema schema;


	public CFSecJpaSecSysGrpIncTable(ICFSecSchema schema) {
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

	protected boolean canCreateSecSysGrpInc(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "createsecsysgrpinc");
		}
		return( permissionGranted );
	}

	protected boolean canReadSecSysGrpInc(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "readsecsysgrpinc");
		}
		return( permissionGranted );
	}

	protected boolean canUpdateSecSysGrpInc(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "updatesecsysgrpinc");
		}
		return( permissionGranted );
	}

	protected boolean canDeleteSecSysGrpInc(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "deletesecsysgrpinc");
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
	public ICFSecSecSysGrpInc createSecSysGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpInc rec )
	{
		final String S_ProcName = "createSecSysGrpInc";
		boolean permissionGranted = canCreateSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "createsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "createSecSysGrpInc", 1, "rec");
		}
		else if (rec instanceof CFSecJpaSecSysGrpInc) {
			CFSecJpaSecSysGrpInc jparec = (CFSecJpaSecSysGrpInc)rec;
			jparec.setCreatedAt(LocalDateTime.now());
			jparec.setUpdatedAt(jparec.getCreatedAt());
			jparec.setCreatedByUserId(Authorization.getSecUserId());
			jparec.setUpdatedByUserId(Authorization.getSecUserId());
			CFSecJpaSecSysGrpInc retval = schema.getJpaHooksSchema().getSecSysGrpIncService().create(jparec);
		return(retval);
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "createSecSysGrpInc", "rec", rec, "CFSecJpaSecSysGrpInc");
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
	public ICFSecSecSysGrpInc updateSecSysGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpInc rec )
	{
		final String S_ProcName = "updateSecSysGrpInc";
		boolean permissionGranted = canUpdateSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "updateSecSysGrpInc", 1, "rec");
		}
		else if (rec instanceof CFSecJpaSecSysGrpInc) {
			CFSecJpaSecSysGrpInc jparec = (CFSecJpaSecSysGrpInc)rec;
			jparec.setUpdatedAt(LocalDateTime.now());
			jparec.setUpdatedByUserId(Authorization.getSecUserId());
			CFSecJpaSecSysGrpInc retval = schema.getJpaHooksSchema().getSecSysGrpIncService().update(jparec);
		return(retval);
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "updateSecSysGrpInc", "rec", rec, "CFSecJpaSecSysGrpInc");
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
	public void deleteSecSysGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpInc rec )
	{
		final String S_ProcName = "deleteSecSysGrpInc";
		boolean permissionGranted = canDeleteSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			return;
		}
		if (rec instanceof CFSecJpaSecSysGrpInc) {
			CFSecJpaSecSysGrpInc jparec = (CFSecJpaSecSysGrpInc)rec;
			schema.getJpaHooksSchema().getSecSysGrpIncService().deleteByIdIdx(jparec.getPKey());
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "deleteSecSysGrpInc", "rec", rec, "CFSecJpaSecSysGrpInc");
		}

		throw new CFLibNotImplementedYetException(getClass(), "deleteSecSysGrpInc");
	}

	/**
	 *	Delete the SecSysGrpInc instance identified by the primary key attributes.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysGrpId	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@param	InclName	The SecSysGrpInc key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecSysGrpIncByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecSysGrpId,
		String argInclName )
	{
		final String S_ProcName = "deleteSecSysGrpIncByIdIdx";
		boolean permissionGranted = canDeleteSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecSysGrpIncService().deleteByIdIdx(argSecSysGrpId,
		argInclName);
	}

	/**
	 *	Delete the SecSysGrpInc instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The primary key identifying the instance to be deleted.
	 */
	@Override
	public void deleteSecSysGrpIncByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncPKey argKey )
	{
		final String S_ProcName = "deleteSecSysGrpIncByIdIdx";
		boolean permissionGranted = canDeleteSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecSysGrpIncService().deleteByIdIdx(argKey.getRequiredSecSysGrpId(),
			argKey.getRequiredInclName());
	}

	/**
	 *	Delete the SecSysGrpInc instances identified by the key SysGrpIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysGrpId	The SecSysGrpInc key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecSysGrpIncBySysGrpIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecSysGrpId )
	{
		final String S_ProcName = "deleteSecSysGrpIncBySysGrpIdx";
		boolean permissionGranted = canDeleteSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecSysGrpIncService().deleteBySysGrpIdx(argSecSysGrpId);
	}


	/**
	 *	Delete the SecSysGrpInc instances identified by the key SysGrpIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecSysGrpIncBySysGrpIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncBySysGrpIdxKey argKey )
	{
		final String S_ProcName = "deleteSecSysGrpIncBySysGrpIdx";
		boolean permissionGranted = canDeleteSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecSysGrpIncService().deleteBySysGrpIdx(argKey.getRequiredSecSysGrpId());
	}

	/**
	 *	Delete the SecSysGrpInc instances identified by the key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	InclName	The SecSysGrpInc key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecSysGrpIncByNameIdx( ICFSecAuthorization Authorization,
		String argInclName )
	{
		final String S_ProcName = "deleteSecSysGrpIncByNameIdx";
		boolean permissionGranted = canDeleteSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecSysGrpIncService().deleteByNameIdx(argInclName);
	}


	/**
	 *	Delete the SecSysGrpInc instances identified by the key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecSysGrpIncByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncByNameIdxKey argKey )
	{
		final String S_ProcName = "deleteSecSysGrpIncByNameIdx";
		boolean permissionGranted = canDeleteSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecSysGrpIncService().deleteByNameIdx(argKey.getRequiredInclName());
	}


	/**
	 *	Read the derived SecSysGrpInc record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecSysGrpInc instance to be read.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecSysGrpInc readDerived( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncPKey PKey )
	{
		final String S_ProcName = "readDerived";
		boolean permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecSysGrpInc retval = schema.getJpaHooksSchema().getSecSysGrpIncService().find(PKey);
		return(retval);
	}

	/**
	 *	Read the derived SecSysGrpInc record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecSysGrpInc readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecSysGrpId,
		String argInclName )
	{
		final String S_ProcName = "readDerived";
		boolean permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecSysGrpInc retval = schema.getJpaHooksSchema().getSecSysGrpIncService().find(argSecSysGrpId,
		argInclName);
		return(retval);
	}

	/**
	 *	Lock the derived SecSysGrpInc record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecSysGrpInc instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecSysGrpInc lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncPKey PKey )
	{
		final String S_ProcName = "lockDerived";
		boolean permissionGranted = canUpdateSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecSysGrpInc retval = schema.getJpaHooksSchema().getSecSysGrpIncService().lockByIdIdx(PKey);
		return(retval);
	}

	/**
	 *	Read all SecSysGrpInc instances.
	 *
	 *	@param	Authorization	The session authorization information.	
	 *
	 *	@return An array of derived record instances, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecSysGrpInc[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllDerived";
		boolean permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		List<CFSecJpaSecSysGrpInc> retlist = schema.getJpaHooksSchema().getSecSysGrpIncService().findAll();
		ICFSecSecSysGrpInc[] retset = new ICFSecSecSysGrpInc[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecSysGrpInc cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the derived SecSysGrpInc record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysGrpId	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@param	InclName	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecSysGrpInc readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecSysGrpId,
		String argInclName )
	{
		final String S_ProcName = "readDerivedByIdIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		ICFSecSecSysGrpInc retval = schema.getJpaHooksSchema().getSecSysGrpIncService().find(argSecSysGrpId,
		argInclName);
		return(retval);
	}

	/**
	 *	Read an array of the derived SecSysGrpInc record instances identified by the duplicate key SysGrpIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysGrpId	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecSysGrpInc[] readDerivedBySysGrpIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecSysGrpId )
	{
		final String S_ProcName = "readDerivedBySysGrpIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaSecSysGrpInc> retlist = schema.getJpaHooksSchema().getSecSysGrpIncService().findBySysGrpIdx(argSecSysGrpId);
		ICFSecSecSysGrpInc[] retset = new ICFSecSecSysGrpInc[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecSysGrpInc cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read an array of the derived SecSysGrpInc record instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	InclName	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecSysGrpInc[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String argInclName )
	{
		final String S_ProcName = "readDerivedByNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaSecSysGrpInc> retlist = schema.getJpaHooksSchema().getSecSysGrpIncService().findByNameIdx(argInclName);
		ICFSecSecSysGrpInc[] retset = new ICFSecSecSysGrpInc[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecSysGrpInc cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the specific SecSysGrpInc record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecSysGrpInc instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysGrpInc readRec( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncPKey PKey )
	{
		final String S_ProcName = "readRec";
		boolean permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRec");
	}

	/**
	 *	Read the specific SecSysGrpInc record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecSysGrpInc instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysGrpInc readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecSysGrpId,
		String argInclName )
	{
		final String S_ProcName = "readRec";
		boolean permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRec-args");
	}

	/**
	 *	Lock the specific SecSysGrpInc record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecSysGrpInc instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysGrpInc lockRec( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpIncPKey PKey )
	{
		final String S_ProcName = "lockRec";
		boolean permissionGranted = canUpdateSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "lockRec");
	}

	/**
	 *	Read all the specific SecSysGrpInc record instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecSysGrpInc instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecSysGrpInc[] readAllRec( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllRec";
		boolean permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readAllRec");
	}


	/**
	 *	Read a page of all the specific SecSysGrpInc record instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecSysGrpInc instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecSysGrpInc[] pageAllRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 priorSecSysGrpId,
		String priorInclName )
	{
		final String S_ProcName = "pageAllRec";
		boolean permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "pageAllRec");
	}

	/**
	 *	Read the specific SecSysGrpInc record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysGrpId	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@param	InclName	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysGrpInc readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecSysGrpId,
		String argInclName )
	{
		final String S_ProcName = "readRecByIdIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByIdIdx");
	}

	/**
	 *	Read an array of the specific SecSysGrpInc record instances identified by the duplicate key SysGrpIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysGrpId	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysGrpInc[] readRecBySysGrpIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecSysGrpId )
	{
		final String S_ProcName = "readRecBySysGrpIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecBySysGrpIdx");
	}

	/**
	 *	Read an array of the specific SecSysGrpInc record instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	InclName	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysGrpInc[] readRecByNameIdx( ICFSecAuthorization Authorization,
		String argInclName )
	{
		final String S_ProcName = "readRecByNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByNameIdx");
	}

	/**
	 *	Read a page array of the specific SecSysGrpInc record instances identified by the duplicate key SysGrpIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysGrpId	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysGrpInc[] pageRecBySysGrpIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecSysGrpId,
		ICFLibKeyHash256 priorSecSysGrpId,
		String priorInclName )
	{
		final String S_ProcName = "pageRecBySysGrpIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "pageRecBySysGrpIdx");
	}

	/**
	 *	Read a page array of the specific SecSysGrpInc record instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	InclName	The SecSysGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysGrpInc[] pageRecByNameIdx( ICFSecAuthorization Authorization,
		String argInclName,
		ICFLibKeyHash256 priorSecSysGrpId,
		String priorInclName )
	{
		final String S_ProcName = "pageRecByNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysGrpInc(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysgrpinc", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysGrpIncTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "pageRecByNameIdx");
	}
}
