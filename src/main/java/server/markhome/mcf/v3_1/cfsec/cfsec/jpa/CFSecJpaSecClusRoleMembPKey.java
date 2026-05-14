// Description: Java JPA implementation of a SecClusRoleMemb primary key object.

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
 *	CFSecJpaSecClusRoleMembPKey Primary Key for SecClusRoleMemb
 *		requiredSecClusRoleId	Required object attribute SecClusRoleId.
 *		requiredLoginId	Required object attribute LoginId.
 */
@Embeddable
public class CFSecJpaSecClusRoleMembPKey
	implements ICFSecSecClusRoleMembPKey, Comparable<ICFSecSecClusRoleMembPKey>, Serializable
{
	@ManyToOne(fetch=FetchType.LAZY, optional=false)
	@JoinColumn( name="SecClusRoleId", referencedColumnName="SecClusRoleId" )
	protected CFSecJpaSecClusRole requiredContainerRole;
	@ManyToOne(fetch=FetchType.LAZY, optional=false)
	@JoinColumn( name="login_id", referencedColumnName="login_id" )
	protected CFSecJpaSecUser requiredParentUser;

	public CFSecJpaSecClusRoleMembPKey() {
		requiredContainerRole = null;
		requiredParentUser = null;
	}

	@Override
	public ICFSecSecClusRole getRequiredContainerRole() {
		return( requiredContainerRole );
	}
	@Override
	public void setRequiredContainerRole(ICFSecSecClusRole argObj) {
		if(argObj == null) {
			throw new CFLibNullArgumentException(getClass(), "setContainerRole", 1, "argObj");
		}
		else if (argObj instanceof CFSecJpaSecClusRole) {
			requiredContainerRole = (CFSecJpaSecClusRole)argObj;
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "setContainerRole", "argObj", argObj, "CFSecJpaSecClusRole");
		}
	
	}

	@Override
	public void setRequiredContainerRole(CFLibDbKeyHash256 argSecClusRoleId) {
		ICFSecSchema targetBackingSchema = ICFSecSchema.getBackingCFSec();
		if (targetBackingSchema == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredContainerRole", 0, "ICFSecSchema.getBackingCFSec()");
		}
		ICFSecSecClusRoleTable targetTable = targetBackingSchema.getTableSecClusRole();
		if (targetTable == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredContainerRole", 0, "ICFSecSchema.getBackingCFSec().getTableSecClusRole()");
		}
		ICFSecSecClusRole targetRec = targetTable.readDerivedByIdIdx(ICFSecSchema.getAuthorizationCallback().getEffectiveAuthorization(), argSecClusRoleId);
		setRequiredContainerRole(targetRec);
	}
	@Override
	public ICFSecSecUser getRequiredParentUser() {
		return( requiredParentUser );
	}
	@Override
	public void setRequiredParentUser(ICFSecSecUser argObj) {
		if(argObj == null) {
			throw new CFLibNullArgumentException(getClass(), "setParentUser", 1, "argObj");
		}
		else if (argObj instanceof CFSecJpaSecUser) {
			requiredParentUser = (CFSecJpaSecUser)argObj;
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "setParentUser", "argObj", argObj, "CFSecJpaSecUser");
		}
	
	}

	@Override
	public void setRequiredParentUser(String argLoginId) {
		ICFSecSchema targetBackingSchema = ICFSecSchema.getBackingCFSec();
		if (targetBackingSchema == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredParentUser", 0, "ICFSecSchema.getBackingCFSec()");
		}
		ICFSecSecUserTable targetTable = targetBackingSchema.getTableSecUser();
		if (targetTable == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredParentUser", 0, "ICFSecSchema.getBackingCFSec().getTableSecUser()");
		}
		ICFSecSecUser targetRec = targetTable.readDerivedByULoginIdx(ICFSecSchema.getAuthorizationCallback().getEffectiveAuthorization(), argLoginId);
		setRequiredParentUser(targetRec);
	}
	@Override
	public CFLibDbKeyHash256 getRequiredSecClusRoleId() {
		ICFSecSecClusRole result = getRequiredContainerRole();
		if (result != null) {
			return result.getRequiredSecClusRoleId();
		}
		else {
			throw new CFLibNullArgumentException(getClass(), "getRequiredSecClusRoleId", 0, "getRequiredContainerRole()");
		}
	}

	@Override
	public String getRequiredLoginId() {
		ICFSecSecUser result = getRequiredParentUser();
		if (result != null) {
			return result.getRequiredLoginId();
		}
		else {
			throw new CFLibNullArgumentException(getClass(), "getRequiredLoginId", 0, "getRequiredParentUser()");
		}
	}

	@Override
	public boolean equals( Object obj ) {
		if (obj == null) {
			return( false );
		}
		else if (obj instanceof ICFSecSecClusRoleMembPKey) {
			ICFSecSecClusRoleMembPKey rhs = (ICFSecSecClusRoleMembPKey)obj;
			if( getRequiredSecClusRoleId() != null ) {
				if( rhs.getRequiredSecClusRoleId() != null ) {
					if( ! getRequiredSecClusRoleId().equals( rhs.getRequiredSecClusRoleId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecClusRoleId() != null ) {
					return( false );
				}
			}
			if( getRequiredLoginId() != null ) {
				if( rhs.getRequiredLoginId() != null ) {
					if( ! getRequiredLoginId().equals( rhs.getRequiredLoginId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredLoginId() != null ) {
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
		hashCode = hashCode + getRequiredSecClusRoleId().hashCode();
		if( getRequiredLoginId() != null ) {
			hashCode = hashCode + getRequiredLoginId().hashCode();
		}
		return( hashCode & 0x7fffffff );
	}

	@Override
	public int compareTo( ICFSecSecClusRoleMembPKey rhs ) {
		int cmp;
		if (rhs == null) {
			return( 1 );
		}
			if (getRequiredSecClusRoleId() != null) {
				if (rhs.getRequiredSecClusRoleId() != null) {
					cmp = getRequiredSecClusRoleId().compareTo( rhs.getRequiredSecClusRoleId() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecClusRoleId() != null) {
				return( -1 );
			}
			if (getRequiredLoginId() != null) {
				if (rhs.getRequiredLoginId() != null) {
					cmp = getRequiredLoginId().compareTo( rhs.getRequiredLoginId() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredLoginId() != null) {
				return( -1 );
			}
		return( 0 );
	}

	@Override
	public String getXmlAttrFragment() {
		String ret = "" 
			+ " RequiredSecClusRoleId=" + "\"" + getRequiredSecClusRoleId().toString() + "\""
			+ " RequiredLoginId=" + "\"" + StringEscapeUtils.escapeXml11( getRequiredLoginId() ) + "\"";
		return( ret );
	}

	@Override
	public String toString() {
		String ret = "<CFSecSecClusRoleMembPKey" + getXmlAttrFragment() + "/>";
		return( ret );
	}
}
