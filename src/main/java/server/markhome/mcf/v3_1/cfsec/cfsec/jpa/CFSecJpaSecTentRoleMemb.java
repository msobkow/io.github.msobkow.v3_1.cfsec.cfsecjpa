// Description: Java 25 JPA implementation of a SecTentRoleMemb entity definition object.

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

@Entity
@Table(
	name = "SecTentRoleMemb", schema = "CFSec31",
	indexes = {
		@Index(name = "SecTentRoleMembIdIdx", columnList = "SecTentRoleId, login_id", unique = true),
		@Index(name = "SecTentRoleMembTentRoleIdx", columnList = "SecTentRoleId", unique = false),
		@Index(name = "SecTentRoleMembLoginIdx", columnList = "login_id", unique = false),
		@Index(name = "SecTentRoleMembTentRoleIdxRole", columnList = "SecTentRoleIdRole", unique = false),
		@Index(name = "SecTentRoleMembLoginIdxUser", columnList = "login_idUser", unique = false)
	}
)
@Transactional(Transactional.TxType.SUPPORTS)
@PersistenceContext(unitName = "CFSecPU")
public class CFSecJpaSecTentRoleMemb
	implements Comparable<Object>,
		ICFSecSecTentRoleMemb,
		Serializable
{
	// Embedded id's are package-accessible so that the Repository can dereference the attributes of the primary key
	@AttributeOverrides({
		@AttributeOverride(name="SecTentRoleId", column = @Column( name="SecTentRoleId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) ),
		@AttributeOverride(name="login_id", column = @Column( name="login_id", nullable=false, length=32 ) )
	})
	@EmbeddedId
	CFSecJpaSecTentRoleMembPKey pkey = new CFSecJpaSecTentRoleMembPKey();
	@ManyToOne(fetch=FetchType.LAZY, optional=false)
	@JoinColumn( name="SecTentRoleIdRole", referencedColumnName="SecTentRoleId" )
	protected CFSecJpaSecTentRole requiredContainerRole;
	@ManyToOne(fetch=FetchType.LAZY, optional=false)
	@JoinColumn( name="login_idUser", referencedColumnName="login_id" )
	protected CFSecJpaSecUser requiredParentUser;
	protected int requiredRevision;


	@AttributeOverrides({
		@AttributeOverride( name="bytes", column = @Column( name="CreatedByUserId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) )
	})
	protected CFLibDbKeyHash256 createdByUserId = CFLibDbKeyHash256.fromHex(ICFSecPubSecUser.S_INIT_CREATED_BY);

	@AttributeOverrides({
		@AttributeOverride( name="bytes", column = @Column( name="CreatedBySessionId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) )
	})
	protected CFLibDbKeyHash256 createdBySessionId = CFLibDbKeyHash256.fromHex(ICFSecPubSecSession.S_SECSESSIONID_INIT_VALUE);

	@Column(name="CreatedAt", nullable=false)
	protected LocalDateTime createdAt = LocalDateTime.now();

	@AttributeOverrides({
		@AttributeOverride( name="bytes", column= @Column( name="UpdatedByUserId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) )
	})
	protected CFLibDbKeyHash256 updatedByUserId = CFLibDbKeyHash256.fromHex(ICFSecPubSecUser.S_INIT_UPDATED_BY);

	@AttributeOverrides({
		@AttributeOverride( name="bytes", column= @Column( name="UpdatedBySessionId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) )
	})
	protected CFLibDbKeyHash256 updatedBySessionId = CFLibDbKeyHash256.fromHex(ICFSecPubSecSession.S_SECSESSIONID_INIT_VALUE);

	@Column(name="UpdatedAt", nullable=false)
	protected LocalDateTime updatedAt = LocalDateTime.now();

	public CFSecJpaSecTentRoleMemb() {
		pkey = new CFSecJpaSecTentRoleMembPKey();
	}

	@Override
	public int getClassCode() {
		return( ICFSecSecTentRoleMemb.CLASS_CODE );
	}

	@Override
	public ICFSecSecTentRole getRequiredContainerRole() {
		return(requiredContainerRole);
	}

	@Override
	public void setRequiredContainerRole(ICFSecSecTentRole argObj) {
		if(argObj == null) {
			throw new CFLibNullArgumentException(getClass(), "setContainerRole", 1, "argObj");
		}
		else if (argObj instanceof CFSecJpaSecTentRole) {
			requiredContainerRole = (CFSecJpaSecTentRole)argObj;
			if (requiredContainerRole != null) {
				getPKey().setRequiredSecTentRoleId(requiredContainerRole.getRequiredSecTentRoleId());
			}
			else {
			}
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "setContainerRole", "argObj", argObj, "CFSecJpaSecTentRole");
		}
	
	}

	@Override
	public void setRequiredContainerRole(ICFSecProtSecTentRole argObj) {
		setRequiredContainerRole(argObj.getRequiredSecTentRoleId());
	}

	@Override
	public void setRequiredContainerRole(ICFLibKeyHash256 argSecTentRoleId) {
		ICFSecSchema targetBackingSchema = ICFSecSchema.getBackingCFSec();
		if (targetBackingSchema == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredContainerRole", 0, "ICFSecSchema.getBackingCFSec()");
		}
		ICFSecSecTentRoleTable targetTable = targetBackingSchema.getTableSecTentRole();
		if (targetTable == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredContainerRole", 0, "ICFSecSchema.getBackingCFSec().getTableSecTentRole()");
		}
		ICFSecSecTentRole targetRec = targetTable.readDerivedByIdIdx(ICFSecSchema.getAuthorizationCallback().getEffectiveAuthorization(), argSecTentRoleId);
		setRequiredContainerRole(targetRec);
	}

	@Override
	public ICFSecSecUser getRequiredParentUser() {
		return(requiredParentUser);
	}

	@Override
	public void setRequiredParentUser(ICFSecSecUser argObj) {
		if(argObj == null) {
			throw new CFLibNullArgumentException(getClass(), "setParentUser", 1, "argObj");
		}
		else if (argObj instanceof CFSecJpaSecUser) {
			requiredParentUser = (CFSecJpaSecUser)argObj;
			if (requiredParentUser != null) {
				getPKey().setRequiredLoginId(requiredParentUser.getRequiredLoginId());
			}
			else {
			}
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "setParentUser", "argObj", argObj, "CFSecJpaSecUser");
		}
	
	}

	@Override
	public void setRequiredParentUser(ICFSecProtSecUser argObj) {
		setRequiredParentUser(argObj.getRequiredLoginId());
	}

	@Override
	public void setRequiredParentUser(ICFSecPubSecUser argObj) {
		setRequiredParentUser(argObj.getRequiredLoginId());
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
	public CFLibDbKeyHash256 getCreatedByUserId() {
		return( createdByUserId );
	}

	@Override
	public void setCreatedByUserId( CFLibDbKeyHash256 value ) {
		if (value == null || value.isNull()) {
			throw new CFLibNullArgumentException(getClass(), "setCreatedByUserId", 1, "value");
		}
		createdByUserId = value;
	}

	@Override
	public LocalDateTime getCreatedAt() {
		return( createdAt );
	}

	@Override
	public void setCreatedAt( LocalDateTime value ) {
		if (value == null) {
			throw new CFLibNullArgumentException(getClass(), "setCreatedAt", 1, "value");
		}
		createdAt = value;
	}

	@Override
	public CFLibDbKeyHash256 getUpdatedByUserId() {
		return( updatedByUserId );
	}

	@Override
	public void setUpdatedByUserId( CFLibDbKeyHash256 value ) {
		if (value == null || value.isNull()) {
			throw new CFLibNullArgumentException(getClass(), "setUpdatedByUserId", 1, "value");
		}
		updatedByUserId = value;
	}

	@Override
	public LocalDateTime getUpdatedAt() {
		return( updatedAt );
	}

	@Override
	public void setUpdatedAt( LocalDateTime value ) {
		if (value == null) {
			throw new CFLibNullArgumentException(getClass(), "setUpdatedAt", 1, "value");
		}
		updatedAt = value;
	}

	@Override
	public ICFSecSecTentRoleMembPKey getPKey() {
		return pkey;
	}

	@Override
	public void setPKey(ICFSecSecTentRoleMembPKey pkey ) {
		if (pkey == null) {
			throw new CFLibNullArgumentException(getClass(), "setPKey", 1, "pkey");
		}
		else if (!(pkey instanceof CFSecJpaSecTentRoleMembPKey)) {
			throw new CFLibUnsupportedClassException(getClass(), "setPKey", "pkey", pkey, "CFSecJpaSecTentRoleMembPKey");
		}
		this.pkey = (CFSecJpaSecTentRoleMembPKey)pkey;
	}

	@Override
	public ICFLibKeyHash256 getRequiredSecTentRoleId() {
		return( pkey.getRequiredSecTentRoleId() );
	}

	@Override
	public void setRequiredSecTentRoleId( ICFLibKeyHash256 requiredSecTentRoleId ) {
		pkey.setRequiredSecTentRoleId( requiredSecTentRoleId );
	}

	@Override
	public String getRequiredLoginId() {
		return( pkey.getRequiredLoginId() );
	}

	@Override
	public void setRequiredLoginId( String requiredLoginId ) {
		pkey.setRequiredLoginId( requiredLoginId );
	}

	@Override
	public int getRequiredRevision() {
		return( requiredRevision );
	}

	@Override
	public void setRequiredRevision( int value ) {
		requiredRevision = value;
	}

	@Override
	public boolean equals( Object obj ) {
		if (obj == null) {
			return( false );
		}
		else if (obj instanceof ICFSecSecTentRoleMemb) {
			ICFSecSecTentRoleMemb rhs = (ICFSecSecTentRoleMemb)obj;
			if( ! getCreatedByUserId().equals( rhs.getCreatedByUserId() ) ) {
				return( false );
			}
			if( ! getCreatedAt().equals( rhs.getCreatedAt() ) ) {
				return( false );
			}
			if( ! getUpdatedByUserId().equals( rhs.getUpdatedByUserId() ) ) {
				return( false );
			}
			if( ! getUpdatedAt().equals( rhs.getUpdatedAt() ) ) {
				return( false );
			}
			if( getRequiredSecTentRoleId() != null ) {
				if( rhs.getRequiredSecTentRoleId() != null ) {
					if( ! getRequiredSecTentRoleId().equals( rhs.getRequiredSecTentRoleId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecTentRoleId() != null ) {
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
		else if (obj instanceof ICFSecSecTentRoleMembH) {
			ICFSecSecTentRoleMembH rhs = (ICFSecSecTentRoleMembH)obj;
			if( ! getCreatedByUserId().equals( rhs.getCreatedByUserId() ) ) {
				return( false );
			}
			if( ! getCreatedAt().equals( rhs.getCreatedAt() ) ) {
				return( false );
			}
			if( ! getUpdatedByUserId().equals( rhs.getUpdatedByUserId() ) ) {
				return( false );
			}
			if( ! getUpdatedAt().equals( rhs.getUpdatedAt() ) ) {
				return( false );
			}
			if( getRequiredSecTentRoleId() != null ) {
				if( rhs.getRequiredSecTentRoleId() != null ) {
					if( ! getRequiredSecTentRoleId().equals( rhs.getRequiredSecTentRoleId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecTentRoleId() != null ) {
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
		else if (obj instanceof ICFSecSecTentRoleMembHPKey) {
			ICFSecSecTentRoleMembHPKey rhs = (ICFSecSecTentRoleMembHPKey)obj;
			if( getRequiredSecTentRoleId() != null ) {
				if( rhs.getRequiredSecTentRoleId() != null ) {
					if( ! getRequiredSecTentRoleId().equals( rhs.getRequiredSecTentRoleId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecTentRoleId() != null ) {
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
		else if (obj instanceof ICFSecSecTentRoleMembByTentRoleIdxKey) {
			ICFSecSecTentRoleMembByTentRoleIdxKey rhs = (ICFSecSecTentRoleMembByTentRoleIdxKey)obj;
			if( getRequiredSecTentRoleId() != null ) {
				if( rhs.getRequiredSecTentRoleId() != null ) {
					if( ! getRequiredSecTentRoleId().equals( rhs.getRequiredSecTentRoleId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecTentRoleId() != null ) {
					return( false );
				}
			}
			return( true );
		}
		else if (obj instanceof ICFSecSecTentRoleMembByUserIdxKey) {
			ICFSecSecTentRoleMembByUserIdxKey rhs = (ICFSecSecTentRoleMembByUserIdxKey)obj;
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
		int hashCode = getPKey().hashCode();
		hashCode = hashCode + getCreatedByUserId().hashCode();
		hashCode = hashCode + getCreatedAt().hashCode();
		hashCode = hashCode + getUpdatedByUserId().hashCode();
		hashCode = hashCode + getUpdatedAt().hashCode();
		hashCode = hashCode + getRequiredSecTentRoleId().hashCode();
		if( getRequiredLoginId() != null ) {
			hashCode = hashCode + getRequiredLoginId().hashCode();
		}
		return( hashCode & 0x7fffffff );
	}

	@Override
	public int compareTo( Object obj ) {
		int cmp;
		if (obj == null) {
			return( 1 );
		}
		else if (obj instanceof ICFSecSecTentRoleMemb) {
			ICFSecSecTentRoleMemb rhs = (ICFSecSecTentRoleMemb)obj;
			if (getPKey() == null) {
				if (rhs.getPKey() != null) {
					return( -1 );
				}
			}
			else {
				if (rhs.getPKey() == null) {
					return( 1 );
				}
				else {
					cmp = getPKey().compareTo(rhs.getPKey());
					if (cmp != 0) {
						return( cmp );
					}
				}
			}
			cmp = getCreatedByUserId().compareTo( rhs.getCreatedByUserId() );
			if( cmp != 0 ) {
				return( cmp );
			}
			cmp = getCreatedAt().compareTo( rhs.getCreatedAt() );
			if( cmp != 0 ) {
				return( cmp );
			}
			cmp = getUpdatedByUserId().compareTo( rhs.getUpdatedByUserId() );
			if( cmp != 0 ) {
				return( cmp );
			}
			cmp = getUpdatedAt().compareTo( rhs.getUpdatedAt() );
			if( cmp != 0 ) {
				return( cmp );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecSecTentRoleMembHPKey) {
			ICFSecSecTentRoleMembHPKey rhs = (ICFSecSecTentRoleMembHPKey)obj;
			if (getRequiredSecTentRoleId() != null) {
				if (rhs.getRequiredSecTentRoleId() != null) {
					cmp = getRequiredSecTentRoleId().compareTo( rhs.getRequiredSecTentRoleId() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecTentRoleId() != null) {
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
		else if( obj instanceof ICFSecSecTentRoleMembH ) {
			ICFSecSecTentRoleMembH rhs = (ICFSecSecTentRoleMembH)obj;
			if (getRequiredSecTentRoleId() != null) {
				if (rhs.getRequiredSecTentRoleId() != null) {
					cmp = getRequiredSecTentRoleId().compareTo( rhs.getRequiredSecTentRoleId() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecTentRoleId() != null) {
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
			cmp = getCreatedByUserId().compareTo( rhs.getCreatedByUserId() );
			if( cmp != 0 ) {
				return( cmp );
			}
			cmp = getCreatedAt().compareTo( rhs.getCreatedAt() );
			if( cmp != 0 ) {
				return( cmp );
			}
			cmp = getUpdatedByUserId().compareTo( rhs.getUpdatedByUserId() );
			if( cmp != 0 ) {
				return( cmp );
			}
			cmp = getUpdatedAt().compareTo( rhs.getUpdatedAt() );
			if( cmp != 0 ) {
				return( cmp );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecSecTentRoleMembByTentRoleIdxKey) {
			ICFSecSecTentRoleMembByTentRoleIdxKey rhs = (ICFSecSecTentRoleMembByTentRoleIdxKey)obj;
			if (getRequiredSecTentRoleId() != null) {
				if (rhs.getRequiredSecTentRoleId() != null) {
					cmp = getRequiredSecTentRoleId().compareTo( rhs.getRequiredSecTentRoleId() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecTentRoleId() != null) {
				return( -1 );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecSecTentRoleMembByUserIdxKey) {
			ICFSecSecTentRoleMembByUserIdxKey rhs = (ICFSecSecTentRoleMembByUserIdxKey)obj;
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
		else {
			throw new CFLibUnsupportedClassException( getClass(),
				"compareTo",
				"obj",
				obj,
				null );
		}
	}

	@Override
	public void set( ICFSecSecTentRoleMemb src ) {
		setSecTentRoleMemb( src );
	}

	@Override
	public void setSecTentRoleMemb( ICFSecSecTentRoleMemb src ) {
		setRequiredContainerRole(src.getRequiredContainerRole());
		setRequiredParentUser(src.getRequiredParentUser());
		setRequiredSecTentRoleId(src.getRequiredSecTentRoleId());
		setRequiredLoginId(src.getRequiredLoginId());
		setRequiredRevision( src.getRequiredRevision() );
		setCreatedByUserId( src.getCreatedByUserId() );
		setCreatedAt( src.getCreatedAt() );
		setUpdatedByUserId( src.getUpdatedByUserId() );
		setUpdatedAt( src.getUpdatedAt() );
	}

	@Override
	public void set( ICFSecSecTentRoleMembH src ) {
		setSecTentRoleMemb( src );
	}

	@Override
	public void setSecTentRoleMemb( ICFSecSecTentRoleMembH src ) {
		setRequiredContainerRole(src.getRequiredSecTentRoleId());
		setRequiredParentUser(src.getRequiredLoginId());
		setRequiredSecTentRoleId(src.getRequiredSecTentRoleId());
		setRequiredLoginId(src.getRequiredLoginId());
	}

	@Override
	public String getXmlAttrFragment() {
		String ret = pkey.getXmlAttrFragment() 
			+ " RequiredRevision=\"" + Integer.toString( getRequiredRevision() ) + "\""
			+ " RequiredSecTentRoleId=" + "\"" + getRequiredSecTentRoleId().toString() + "\""
			+ " RequiredLoginId=" + "\"" + StringEscapeUtils.escapeXml11( getRequiredLoginId() ) + "\"";
		return( ret );
	}

	@Override
	public String toString() {
		String ret = "<CFSecJpaSecTentRoleMemb" + getXmlAttrFragment() + "/>";
		return( ret );
	}
}
