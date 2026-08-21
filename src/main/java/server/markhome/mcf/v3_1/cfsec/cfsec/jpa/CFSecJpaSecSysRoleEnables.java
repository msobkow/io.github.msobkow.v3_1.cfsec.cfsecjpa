// Description: Java 25 JPA implementation of a SecSysRoleEnables entity definition object.

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
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

@Entity
@Table(
	name = "SecSysRoleEnables", schema = "CFSec31",
	indexes = {
		@Index(name = "SecSysRoleEnablesIdIdx", columnList = "SecSysRoleId, enable_name", unique = true),
		@Index(name = "SecSysRoleEnablesRoleIdx", columnList = "SecSysRoleId", unique = false),
		@Index(name = "SecSysRoleEnableNameIdx", columnList = "enable_name", unique = false),
		@Index(name = "SecSysRoleEnablesRoleIdxSysRole", columnList = "SecSysRoleIdSysRole", unique = false),
		@Index(name = "SecSysRoleEnableNameIdxEnableGroup", columnList = "enable_nameEnableGroup", unique = false)
	}
)
@Transactional(Transactional.TxType.REQUIRED)
@PersistenceContext(unitName = "CFSecPU")
public class CFSecJpaSecSysRoleEnables
	implements Comparable<Object>,
		ICFSecSecSysRoleEnables,
		Serializable
{
	// Embedded id's are package-accessible so that the Repository can dereference the attributes of the primary key
	@AttributeOverrides({
		@AttributeOverride(name="SecSysRoleId", column = @Column( name="SecSysRoleId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) ),
		@AttributeOverride(name="enable_name", column = @Column( name="enable_name", nullable=false, length=64 ) )
	})
	@EmbeddedId
	CFSecJpaSecSysRoleEnablesPKey pkey = new CFSecJpaSecSysRoleEnablesPKey();
	@ManyToOne(fetch=FetchType.LAZY, optional=false)
	@JoinColumn( name="SecSysRoleIdSysRole", referencedColumnName="SecSysRoleId" )
	protected CFSecJpaSecSysRole $OptionalOrRequired$ContainerSysRole;
	@ManyToOne(fetch=FetchType.LAZY, optional=false)
	@JoinColumn( name="enable_nameEnableGroup", referencedColumnName="safe_name" )
	protected CFSecJpaSecSysGrp $OptionalOrRequired$ParentEnableGroup;
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

	public CFSecJpaSecSysRoleEnables() {
		pkey = new CFSecJpaSecSysRoleEnablesPKey();
	}

	@Override
	public int getClassCode() {
		return( ICFSecSecSysRoleEnables.CLASS_CODE );
	}

	@Override
	public ICFSecSecSysRole get$OptionalOrRequired$ContainerSysRole() {
		return($OptionalOrRequired$ContainerSysRole);
	}

	@Override
	public void set$OptionalOrRequired$ContainerSysRole(ICFSecSecSysRole argObj) {
		if(argObj == null) {
			throw new CFLibNullArgumentException(getClass(), "setContainerSysRole", 1, "argObj");
		}
		else if (argObj instanceof CFSecJpaSecSysRole) {
			$OptionalOrRequired$ContainerSysRole = (CFSecJpaSecSysRole)argObj;
			if ($OptionalOrRequired$ContainerSysRole != null) {
				getPKey().setRequiredSecSysRoleId($OptionalOrRequired$ContainerSysRole.getRequiredSecSysRoleId());
			}
			else {
			}
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "setContainerSysRole", "argObj", argObj, "CFSecJpaSecSysRole");
		}
	
	}

	@Override
	public void set$OptionalOrRequired$ContainerSysRole(ICFSecProtSecSysRole argObj) {
		set$OptionalOrRequired$ContainerSysRole(argObj.getRequiredSecSysRoleId());
	}

	@Override
	public void set$OptionalOrRequired$ContainerSysRole(ICFSecPubSecSysRole argObj) {
		set$OptionalOrRequired$ContainerSysRole(argObj.getRequiredSecSysRoleId());
	}

	@Override
	public void set$OptionalOrRequired$ContainerSysRole(ICFLibKeyHash256 argSecSysRoleId) {
		ICFSecSchema targetBackingSchema = ICFSecSchema.getBackingCFSec();
		if (targetBackingSchema == null) {
			throw new CFLibNullArgumentException(getClass(), "set$OptionalOrRequired$ContainerSysRole", 0, "ICFSecSchema.getBackingCFSec()");
		}
		ICFSecSecSysRoleTable targetTable = targetBackingSchema.getTableSecSysRole();
		if (targetTable == null) {
			throw new CFLibNullArgumentException(getClass(), "set$OptionalOrRequired$ContainerSysRole", 0, "ICFSecSchema.getBackingCFSec().getTableSecSysRole()");
		}
		ICFSecSecSysRole targetRec = targetTable.readDerivedByIdIdx(ICFSecSchema.getAuthorizationCallback().getEffectiveAuthorization(), argSecSysRoleId);
		set$OptionalOrRequired$ContainerSysRole(targetRec);
	}

	@Override
	public ICFSecSecSysGrp get$OptionalOrRequired$ParentEnableGroup() {
		return($OptionalOrRequired$ParentEnableGroup);
	}

	@Override
	public void set$OptionalOrRequired$ParentEnableGroup(ICFSecSecSysGrp argObj) {
		if(argObj == null) {
			throw new CFLibNullArgumentException(getClass(), "setParentEnableGroup", 1, "argObj");
		}
		else if (argObj instanceof CFSecJpaSecSysGrp) {
			$OptionalOrRequired$ParentEnableGroup = (CFSecJpaSecSysGrp)argObj;
			if ($OptionalOrRequired$ParentEnableGroup != null) {
				getPKey().setRequiredEnableName($OptionalOrRequired$ParentEnableGroup.getRequiredName());
			}
			else {
			}
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "setParentEnableGroup", "argObj", argObj, "CFSecJpaSecSysGrp");
		}
	
	}

	@Override
	public void set$OptionalOrRequired$ParentEnableGroup(ICFSecProtSecSysGrp argObj) {
		set$OptionalOrRequired$ParentEnableGroup(argObj.getRequiredName());
	}

	@Override
	public void set$OptionalOrRequired$ParentEnableGroup(ICFSecPubSecSysGrp argObj) {
		set$OptionalOrRequired$ParentEnableGroup(argObj.getRequiredName());
	}

	@Override
	public void set$OptionalOrRequired$ParentEnableGroup(String argEnableName) {
		ICFSecSchema targetBackingSchema = ICFSecSchema.getBackingCFSec();
		if (targetBackingSchema == null) {
			throw new CFLibNullArgumentException(getClass(), "set$OptionalOrRequired$ParentEnableGroup", 0, "ICFSecSchema.getBackingCFSec()");
		}
		ICFSecSecSysGrpTable targetTable = targetBackingSchema.getTableSecSysGrp();
		if (targetTable == null) {
			throw new CFLibNullArgumentException(getClass(), "set$OptionalOrRequired$ParentEnableGroup", 0, "ICFSecSchema.getBackingCFSec().getTableSecSysGrp()");
		}
		ICFSecSecSysGrp targetRec = targetTable.readDerivedByUNameIdx(ICFSecSchema.getAuthorizationCallback().getEffectiveAuthorization(), argEnableName);
		set$OptionalOrRequired$ParentEnableGroup(targetRec);
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
	public ICFSecSecSysRoleEnablesPKey getPKey() {
		return pkey;
	}

	@Override
	public void setPKey(ICFSecSecSysRoleEnablesPKey pkey ) {
		if (pkey == null) {
			throw new CFLibNullArgumentException(getClass(), "setPKey", 1, "pkey");
		}
		else if (!(pkey instanceof CFSecJpaSecSysRoleEnablesPKey)) {
			throw new CFLibUnsupportedClassException(getClass(), "setPKey", "pkey", pkey, "CFSecJpaSecSysRoleEnablesPKey");
		}
		this.pkey = (CFSecJpaSecSysRoleEnablesPKey)pkey;
	}

	@Override
	public ICFLibKeyHash256 getRequiredSecSysRoleId() {
		return( pkey.getRequiredSecSysRoleId() );
	}

	@Override
	public void setRequiredSecSysRoleId( ICFLibKeyHash256 requiredSecSysRoleId ) {
		pkey.setRequiredSecSysRoleId( requiredSecSysRoleId );
	}

	@Override
	public String getRequiredEnableName() {
		return( pkey.getRequiredEnableName() );
	}

	@Override
	public void setRequiredEnableName( String requiredEnableName ) {
		pkey.setRequiredEnableName( requiredEnableName );
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
		else if (obj instanceof ICFSecSecSysRoleEnables) {
			ICFSecSecSysRoleEnables rhs = (ICFSecSecSysRoleEnables)obj;
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
			if( getRequiredSecSysRoleId() != null ) {
				if( rhs.getRequiredSecSysRoleId() != null ) {
					if( ! getRequiredSecSysRoleId().equals( rhs.getRequiredSecSysRoleId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecSysRoleId() != null ) {
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
		else if (obj instanceof ICFSecSecSysRoleEnablesH) {
			ICFSecSecSysRoleEnablesH rhs = (ICFSecSecSysRoleEnablesH)obj;
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
			if( getRequiredSecSysRoleId() != null ) {
				if( rhs.getRequiredSecSysRoleId() != null ) {
					if( ! getRequiredSecSysRoleId().equals( rhs.getRequiredSecSysRoleId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecSysRoleId() != null ) {
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
		else if (obj instanceof ICFSecSecSysRoleEnablesHPKey) {
			ICFSecSecSysRoleEnablesHPKey rhs = (ICFSecSecSysRoleEnablesHPKey)obj;
			if( getRequiredSecSysRoleId() != null ) {
				if( rhs.getRequiredSecSysRoleId() != null ) {
					if( ! getRequiredSecSysRoleId().equals( rhs.getRequiredSecSysRoleId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecSysRoleId() != null ) {
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
		else if (obj instanceof ICFSecSecSysRoleEnablesBySysRoleIdxKey) {
			ICFSecSecSysRoleEnablesBySysRoleIdxKey rhs = (ICFSecSecSysRoleEnablesBySysRoleIdxKey)obj;
			if( getRequiredSecSysRoleId() != null ) {
				if( rhs.getRequiredSecSysRoleId() != null ) {
					if( ! getRequiredSecSysRoleId().equals( rhs.getRequiredSecSysRoleId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecSysRoleId() != null ) {
					return( false );
				}
			}
			return( true );
		}
		else if (obj instanceof ICFSecSecSysRoleEnablesByNameIdxKey) {
			ICFSecSecSysRoleEnablesByNameIdxKey rhs = (ICFSecSecSysRoleEnablesByNameIdxKey)obj;
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
		int hashCode = getPKey().hashCode();
		hashCode = hashCode + getCreatedByUserId().hashCode();
		hashCode = hashCode + getCreatedAt().hashCode();
		hashCode = hashCode + getUpdatedByUserId().hashCode();
		hashCode = hashCode + getUpdatedAt().hashCode();
		hashCode = hashCode + getRequiredSecSysRoleId().hashCode();
		if( getRequiredEnableName() != null ) {
			hashCode = hashCode + getRequiredEnableName().hashCode();
		}
		return( hashCode & 0x7fffffff );
	}

	@Override
	public int compareTo( Object obj ) {
		int cmp;
		if (obj == null) {
			return( 1 );
		}
		else if (obj instanceof ICFSecSecSysRoleEnables) {
			ICFSecSecSysRoleEnables rhs = (ICFSecSecSysRoleEnables)obj;
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
		else if (obj instanceof ICFSecSecSysRoleEnablesHPKey) {
			ICFSecSecSysRoleEnablesHPKey rhs = (ICFSecSecSysRoleEnablesHPKey)obj;
			if (getRequiredSecSysRoleId() != null) {
				if (rhs.getRequiredSecSysRoleId() != null) {
					cmp = getRequiredSecSysRoleId().compareTo( rhs.getRequiredSecSysRoleId() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecSysRoleId() != null) {
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
		else if( obj instanceof ICFSecSecSysRoleEnablesH ) {
			ICFSecSecSysRoleEnablesH rhs = (ICFSecSecSysRoleEnablesH)obj;
			if (getRequiredSecSysRoleId() != null) {
				if (rhs.getRequiredSecSysRoleId() != null) {
					cmp = getRequiredSecSysRoleId().compareTo( rhs.getRequiredSecSysRoleId() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecSysRoleId() != null) {
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
		else if (obj instanceof ICFSecSecSysRoleEnablesBySysRoleIdxKey) {
			ICFSecSecSysRoleEnablesBySysRoleIdxKey rhs = (ICFSecSecSysRoleEnablesBySysRoleIdxKey)obj;
			if (getRequiredSecSysRoleId() != null) {
				if (rhs.getRequiredSecSysRoleId() != null) {
					cmp = getRequiredSecSysRoleId().compareTo( rhs.getRequiredSecSysRoleId() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecSysRoleId() != null) {
				return( -1 );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecSecSysRoleEnablesByNameIdxKey) {
			ICFSecSecSysRoleEnablesByNameIdxKey rhs = (ICFSecSecSysRoleEnablesByNameIdxKey)obj;
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
		else {
			throw new CFLibUnsupportedClassException( getClass(),
				"compareTo",
				"obj",
				obj,
				null );
		}
	}

	@Override
	public void set( ICFSecSecSysRoleEnables src ) {
		setSecSysRoleEnables( src );
	}

	@Override
	public void setSecSysRoleEnables( ICFSecSecSysRoleEnables src ) {
		set$OptionalOrRequired$ContainerSysRole(src.get$OptionalOrRequired$ContainerSysRole());
		set$OptionalOrRequired$ParentEnableGroup(src.get$OptionalOrRequired$ParentEnableGroup());
		setRequiredSecSysRoleId(src.getRequiredSecSysRoleId());
		setRequiredEnableName(src.getRequiredEnableName());
		setRequiredRevision( src.getRequiredRevision() );
		setCreatedByUserId( src.getCreatedByUserId() );
		setCreatedAt( src.getCreatedAt() );
		setUpdatedByUserId( src.getUpdatedByUserId() );
		setUpdatedAt( src.getUpdatedAt() );
	}

	@Override
	public void set( ICFSecSecSysRoleEnablesH src ) {
		setSecSysRoleEnables( src );
	}

	@Override
	public void setSecSysRoleEnables( ICFSecSecSysRoleEnablesH src ) {
		set$OptionalOrRequired$ContainerSysRole(src.getRequiredSecSysRoleId());
		set$OptionalOrRequired$ParentEnableGroup(src.getRequiredEnableName());
		setRequiredSecSysRoleId(src.getRequiredSecSysRoleId());
		setRequiredEnableName(src.getRequiredEnableName());
	}

	@Override
	public String getXmlAttrFragment() {
		String ret = pkey.getXmlAttrFragment() 
			+ " RequiredRevision=\"" + Integer.toString( getRequiredRevision() ) + "\""
			+ " RequiredSecSysRoleId=" + "\"" + getRequiredSecSysRoleId().toString() + "\""
			+ " RequiredEnableName=" + "\"" + StringEscapeUtils.escapeXml11( getRequiredEnableName() ) + "\"";
		return( ret );
	}

	@Override
	public String toString() {
		String ret = "<CFSecJpaSecSysRoleEnables" + getXmlAttrFragment() + "/>";
		return( ret );
	}
}
