// Description: Java 25 JPA implementation of a SecClusRoleMemb entity definition object.

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
	name = "SecClusRoleMemb", schema = "CFSec31",
	indexes = {
		@Index(name = "SecClusRoleMembIdIdx", columnList = "SecClusRoleId, login_id", unique = true),
		@Index(name = "SecClusRoleMembClusRoleIdx", columnList = "SecClusRoleId", unique = false),
		@Index(name = "SecClusRoleMembLoginIdx", columnList = "login_id", unique = false),
		@Index(name = "SecClusRoleMembClusRoleIdxRole", columnList = "SecClusRoleIdRole", unique = false),
		@Index(name = "SecClusRoleMembLoginIdxUser", columnList = "login_idUser", unique = false)
	}
)
@Transactional(Transactional.TxType.SUPPORTS)
@PersistenceContext(unitName = "CFSecPU")
public class CFSecJpaSecClusRoleMemb
	implements Comparable<Object>,
		ICFSecSecClusRoleMemb,
		Serializable
{
	// Embedded id's are package-accessible so that the Repository can dereference the attributes of the primary key
	@AttributeOverrides({
		@AttributeOverride(name="SecClusRoleId", column = @Column( name="SecClusRoleId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) ),
		@AttributeOverride(name="login_id", column = @Column( name="login_id", nullable=false, length=32 ) )
	})
	@EmbeddedId
	CFSecJpaSecClusRoleMembPKey pkey = new CFSecJpaSecClusRoleMembPKey();
	@ManyToOne(fetch=FetchType.LAZY, optional=false)
	@JoinColumn( name="SecClusRoleIdRole", referencedColumnName="SecClusRoleId" )
	protected CFSecJpaSecClusRole requiredContainerRole;
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

	public CFSecJpaSecClusRoleMemb() {
		pkey = new CFSecJpaSecClusRoleMembPKey();
	}

	@Override
	public int getClassCode() {
		return( ICFSecSecClusRoleMemb.CLASS_CODE );
	}

	@Override
	public ICFSecSecClusRole getRequiredContainerRole() {
		return(requiredContainerRole);
	}

	@Override
	public void setRequiredContainerRole(ICFSecSecClusRole argObj) {
		if(argObj == null) {
			throw new CFLibNullArgumentException(getClass(), "setContainerRole", 1, "argObj");
		}
		else if (argObj instanceof CFSecJpaSecClusRole) {
			requiredContainerRole = (CFSecJpaSecClusRole)argObj;
			if (requiredContainerRole != null) {
				getPKey().setRequiredSecClusRoleId(requiredContainerRole.getRequiredSecClusRoleId());
			}
			else {
			}
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "setContainerRole", "argObj", argObj, "CFSecJpaSecClusRole");
		}
	
	}

	@Override
	public void setRequiredContainerRole(ICFSecProtSecClusRole argObj) {
		setRequiredContainerRole(argObj.getRequiredSecClusRoleId());
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
	public ICFSecSecClusRoleMembPKey getPKey() {
		return pkey;
	}

	@Override
	public void setPKey(ICFSecSecClusRoleMembPKey pkey ) {
		if (pkey == null) {
			throw new CFLibNullArgumentException(getClass(), "setPKey", 1, "pkey");
		}
		else if (!(pkey instanceof CFSecJpaSecClusRoleMembPKey)) {
			throw new CFLibUnsupportedClassException(getClass(), "setPKey", "pkey", pkey, "CFSecJpaSecClusRoleMembPKey");
		}
		this.pkey = (CFSecJpaSecClusRoleMembPKey)pkey;
	}

	@Override
	public CFLibDbKeyHash256 getRequiredSecClusRoleId() {
		return( pkey.getRequiredSecClusRoleId() );
	}

	@Override
	public void setRequiredSecClusRoleId( CFLibDbKeyHash256 requiredSecClusRoleId ) {
		pkey.setRequiredSecClusRoleId( requiredSecClusRoleId );
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
		else if (obj instanceof ICFSecSecClusRoleMemb) {
			ICFSecSecClusRoleMemb rhs = (ICFSecSecClusRoleMemb)obj;
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
		else if (obj instanceof ICFSecSecClusRoleMembH) {
			ICFSecSecClusRoleMembH rhs = (ICFSecSecClusRoleMembH)obj;
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
		else if (obj instanceof ICFSecSecClusRoleMembHPKey) {
			ICFSecSecClusRoleMembHPKey rhs = (ICFSecSecClusRoleMembHPKey)obj;
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
		else if (obj instanceof ICFSecSecClusRoleMembByClusRoleIdxKey) {
			ICFSecSecClusRoleMembByClusRoleIdxKey rhs = (ICFSecSecClusRoleMembByClusRoleIdxKey)obj;
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
			return( true );
		}
		else if (obj instanceof ICFSecSecClusRoleMembByLoginIdxKey) {
			ICFSecSecClusRoleMembByLoginIdxKey rhs = (ICFSecSecClusRoleMembByLoginIdxKey)obj;
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
		hashCode = hashCode + getRequiredSecClusRoleId().hashCode();
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
		else if (obj instanceof ICFSecSecClusRoleMemb) {
			ICFSecSecClusRoleMemb rhs = (ICFSecSecClusRoleMemb)obj;
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
		else if (obj instanceof ICFSecSecClusRoleMembHPKey) {
			ICFSecSecClusRoleMembHPKey rhs = (ICFSecSecClusRoleMembHPKey)obj;
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
		else if( obj instanceof ICFSecSecClusRoleMembH ) {
			ICFSecSecClusRoleMembH rhs = (ICFSecSecClusRoleMembH)obj;
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
		else if (obj instanceof ICFSecSecClusRoleMembByClusRoleIdxKey) {
			ICFSecSecClusRoleMembByClusRoleIdxKey rhs = (ICFSecSecClusRoleMembByClusRoleIdxKey)obj;
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
			return( 0 );
		}
		else if (obj instanceof ICFSecSecClusRoleMembByLoginIdxKey) {
			ICFSecSecClusRoleMembByLoginIdxKey rhs = (ICFSecSecClusRoleMembByLoginIdxKey)obj;
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
	public void set( ICFSecSecClusRoleMemb src ) {
		setSecClusRoleMemb( src );
	}

	@Override
	public void setSecClusRoleMemb( ICFSecSecClusRoleMemb src ) {
		setRequiredContainerRole(src.getRequiredContainerRole());
		setRequiredParentUser(src.getRequiredParentUser());
		setRequiredSecClusRoleId(src.getRequiredSecClusRoleId());
		setRequiredLoginId(src.getRequiredLoginId());
		setRequiredRevision( src.getRequiredRevision() );
		setCreatedByUserId( src.getCreatedByUserId() );
		setCreatedAt( src.getCreatedAt() );
		setUpdatedByUserId( src.getUpdatedByUserId() );
		setUpdatedAt( src.getUpdatedAt() );
	}

	@Override
	public void set( ICFSecSecClusRoleMembH src ) {
		setSecClusRoleMemb( src );
	}

	@Override
	public void setSecClusRoleMemb( ICFSecSecClusRoleMembH src ) {
		setRequiredContainerRole(src.getRequiredSecClusRoleId());
		setRequiredParentUser(src.getRequiredLoginId());
		setRequiredSecClusRoleId(src.getRequiredSecClusRoleId());
		setRequiredLoginId(src.getRequiredLoginId());
	}

	@Override
	public String getXmlAttrFragment() {
		String ret = pkey.getXmlAttrFragment() 
			+ " RequiredRevision=\"" + Integer.toString( getRequiredRevision() ) + "\""
			+ " RequiredSecClusRoleId=" + "\"" + getRequiredSecClusRoleId().toString() + "\""
			+ " RequiredLoginId=" + "\"" + StringEscapeUtils.escapeXml11( getRequiredLoginId() ) + "\"";
		return( ret );
	}

	@Override
	public String toString() {
		String ret = "<CFSecJpaSecClusRoleMemb" + getXmlAttrFragment() + "/>";
		return( ret );
	}
}
