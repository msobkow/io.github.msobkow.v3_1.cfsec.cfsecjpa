// Description: Java JPA implementation of a SecRoleEnables primary key object.

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

import java.io.Serializable;
import java.math.*;
import java.time.*;
import java.util.*;
import jakarta.persistence.*;
import jakarta.transaction.Transactional;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *	CFSecJpaSecRoleEnablesPKey Primary Key for SecRoleEnables
 *		requiredSecRoleId	Required object attribute SecRoleId.
 *		requiredEnableName	Required object attribute EnableName.
 */
@Embeddable
public class CFSecJpaSecRoleEnablesPKey
	implements ICFSecSecRoleEnablesPKey, Comparable<ICFSecSecRoleEnablesPKey>, Serializable
{
	@ManyToOne(fetch=FetchType.LAZY, optional=false)
	@JoinColumn( name="SecRoleId", referencedColumnName="SecRoleId" )
	protected CFSecJpaSecRole requiredContainerRole;
	@ManyToOne(fetch=FetchType.LAZY, optional=false)
	@JoinColumn( name="enable_name", referencedColumnName="safe_name" )
	protected CFSecJpaSecSysGrp requiredParentEnableGroup;

	public CFSecJpaSecRoleEnablesPKey() {
		requiredContainerRole = null;
		requiredParentEnableGroup = null;
	}

	@Override
	public ICFSecSecRole getRequiredContainerRole() {
		return( requiredContainerRole );
	}
	@Override
	public void setRequiredContainerRole(ICFSecSecRole argObj) {
		if(argObj == null) {
			throw new CFLibNullArgumentException(getClass(), "setContainerRole", 1, "argObj");
		}
		else if (argObj instanceof CFSecJpaSecRole) {
			requiredContainerRole = (CFSecJpaSecRole)argObj;
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "setContainerRole", "argObj", argObj, "CFSecJpaSecRole");
		}
	
	}

	@Override
	public void setRequiredContainerRole(CFLibDbKeyHash256 argSecRoleId) {
		ICFSecSchema targetBackingSchema = ICFSecSchema.getBackingCFSec();
		if (targetBackingSchema == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredContainerRole", 0, "ICFSecSchema.getBackingCFSec()");
		}
		ICFSecSecRoleTable targetTable = targetBackingSchema.getTableSecRole();
		if (targetTable == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredContainerRole", 0, "ICFSecSchema.getBackingCFSec().getTableSecRole()");
		}
		ICFSecSecRole targetRec = targetTable.readDerivedByIdIdx(ICFSecSchema.getAuthorizationCallback().getEffectiveAuthorization(), argSecRoleId);
		setRequiredContainerRole(targetRec);
	}
	@Override
	public ICFSecSecSysGrp getRequiredParentEnableGroup() {
		return( requiredParentEnableGroup );
	}
	@Override
	public void setRequiredParentEnableGroup(ICFSecSecSysGrp argObj) {
		if(argObj == null) {
			throw new CFLibNullArgumentException(getClass(), "setParentEnableGroup", 1, "argObj");
		}
		else if (argObj instanceof CFSecJpaSecSysGrp) {
			requiredParentEnableGroup = (CFSecJpaSecSysGrp)argObj;
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "setParentEnableGroup", "argObj", argObj, "CFSecJpaSecSysGrp");
		}
	
	}

	@Override
	public void setRequiredParentEnableGroup(String argEnableName) {
		ICFSecSchema targetBackingSchema = ICFSecSchema.getBackingCFSec();
		if (targetBackingSchema == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredParentEnableGroup", 0, "ICFSecSchema.getBackingCFSec()");
		}
		ICFSecSecSysGrpTable targetTable = targetBackingSchema.getTableSecSysGrp();
		if (targetTable == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredParentEnableGroup", 0, "ICFSecSchema.getBackingCFSec().getTableSecSysGrp()");
		}
		ICFSecSecSysGrp targetRec = targetTable.readDerivedByUNameIdx(ICFSecSchema.getAuthorizationCallback().getEffectiveAuthorization(), argEnableName);
		setRequiredParentEnableGroup(targetRec);
	}
	@Override
	public CFLibDbKeyHash256 getRequiredSecRoleId() {
		ICFSecSecRole result = getRequiredContainerRole();
		if (result != null) {
			return result.getRequiredSecRoleId();
		}
		else {
			throw new CFLibNullArgumentException(getClass(), "getRequiredSecRoleId", 0, "getRequiredContainerRole()");
		}
	}

	@Override
	public String getRequiredEnableName() {
		ICFSecSecSysGrp result = getRequiredParentEnableGroup();
		if (result != null) {
			return result.getRequiredName();
		}
		else {
			throw new CFLibNullArgumentException(getClass(), "getRequiredEnableName", 0, "getRequiredParentEnableGroup()");
		}
	}

	@Override
	public boolean equals( Object obj ) {
		if (obj == null) {
			return( false );
		}
		else if (obj instanceof ICFSecSecRoleEnablesPKey) {
			ICFSecSecRoleEnablesPKey rhs = (ICFSecSecRoleEnablesPKey)obj;
			if( getRequiredSecRoleId() != null ) {
				if( rhs.getRequiredSecRoleId() != null ) {
					if( ! getRequiredSecRoleId().equals( rhs.getRequiredSecRoleId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecRoleId() != null ) {
					return( false );
				}
			}
			if( getRequiredEnableName() != null ) {
				if( rhs.getRequiredEnableName() != null ) {
					if( ! getRequiredEnableName().equals( rhs.getRequiredEnableName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredEnableName() != null ) {
					return( false );
				}
			}
			return( true );
		}
		else {
			return( false );
		}
	}

	@Override
	public int hashCode() {
		int hashCode = 0;
		hashCode = hashCode + getRequiredSecRoleId().hashCode();
		if( getRequiredEnableName() != null ) {
			hashCode = hashCode + getRequiredEnableName().hashCode();
		}
		return( hashCode & 0x7fffffff );
	}

	@Override
	public int compareTo( ICFSecSecRoleEnablesPKey rhs ) {
		int cmp;
		if (rhs == null) {
			return( 1 );
		}
			if (getRequiredSecRoleId() != null) {
				if (rhs.getRequiredSecRoleId() != null) {
					cmp = getRequiredSecRoleId().compareTo( rhs.getRequiredSecRoleId() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecRoleId() != null) {
				return( -1 );
			}
			if (getRequiredEnableName() != null) {
				if (rhs.getRequiredEnableName() != null) {
					cmp = getRequiredEnableName().compareTo( rhs.getRequiredEnableName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredEnableName() != null) {
				return( -1 );
			}
		return( 0 );
	}

	@Override
	public String getXmlAttrFragment() {
		String ret = "" 
			+ " RequiredSecRoleId=" + "\"" + getRequiredSecRoleId().toString() + "\""
			+ " RequiredEnableName=" + "\"" + StringEscapeUtils.escapeXml11( getRequiredEnableName() ) + "\"";
		return( ret );
	}

	@Override
	public String toString() {
		String ret = "<CFSecSecRoleEnablesPKey" + getXmlAttrFragment() + "/>";
		return( ret );
	}
}
