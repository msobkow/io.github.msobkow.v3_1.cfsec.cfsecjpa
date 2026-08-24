// Description: Java 25 JPA implementation of a ISOCtryLang entity definition object.

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
	name = "iso_cntrylng", schema = "CFSec31",
	indexes = {
		@Index(name = "ISOCtryLangIdIdx", columnList = "ISOCtryId, ISOLangId", unique = true),
		@Index(name = "ISOCtryLangCtryIdx", columnList = "ISOCtryId", unique = false),
		@Index(name = "ISOCtryLangLangIdx", columnList = "ISOLangId", unique = false),
		@Index(name = "ISOCtryLangCtryIdxCtry", columnList = "ISOCtryIdCtry", unique = false),
		@Index(name = "ISOCtryLangLangIdxLang", columnList = "ISOLangIdLang", unique = false)
	}
)
@Transactional(Transactional.TxType.REQUIRED)
@PersistenceContext(unitName = "CFSecPU")
public class CFSecJpaISOCtryLang
	implements Comparable<Object>,
		ICFSecISOCtryLang,
		Serializable
{
	// Embedded id's are package-accessible so that the Repository can dereference the attributes of the primary key
	@AttributeOverrides({
		@AttributeOverride(name="ISOCtryId", column = @Column( name="ISOCtryId", nullable=false ) ),
		@AttributeOverride(name="ISOLangId", column = @Column( name="ISOLangId", nullable=false ) )
	})
	@EmbeddedId
	CFSecJpaISOCtryLangPKey pkey = new CFSecJpaISOCtryLangPKey();
	@ManyToOne(fetch=FetchType.LAZY, optional=false)
	@JoinColumn( name="ISOCtryIdCtry", referencedColumnName="ISOCtryId" )
	protected CFSecJpaISOCtry requiredContainerCtry;
	@ManyToOne(fetch=FetchType.LAZY, optional=false)
	@JoinColumn( name="ISOLangIdLang", referencedColumnName="ISOLangId" )
	protected CFSecJpaISOLang requiredParentLang;
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

	public CFSecJpaISOCtryLang() {
		pkey = new CFSecJpaISOCtryLangPKey();
	}

	@Override
	public int getClassCode() {
		return( ICFSecISOCtryLang.CLASS_CODE );
	}

	@Override
	public ICFSecISOCtry getRequiredContainerCtry() {
		return(requiredContainerCtry);
	}

	@Override
	public void setRequiredContainerCtry(ICFSecISOCtry argObj) {
		if(argObj == null) {
			throw new CFLibNullArgumentException(getClass(), "setContainerCtry", 1, "argObj");
		}
		else if (argObj instanceof CFSecJpaISOCtry) {
			requiredContainerCtry = (CFSecJpaISOCtry)argObj;
			if (requiredContainerCtry != null) {
				getPKey().setRequiredISOCtryId(requiredContainerCtry.getRequiredISOCtryId());
			}
			else {
			}
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "setContainerCtry", "argObj", argObj, "CFSecJpaISOCtry");
		}
	
	}

	@Override
	public void setRequiredContainerCtry(ICFSecProtISOCtry argObj) {
		setRequiredContainerCtry(argObj.getRequiredISOCtryId());
	}

	@Override
	public void setRequiredContainerCtry(ICFSecPubISOCtry argObj) {
		setRequiredContainerCtry(argObj.getRequiredISOCtryId());
	}

	@Override
	public void setRequiredContainerCtry($implIJavaAtomType$ argISOCtryId) {
		ICFSecSchema targetBackingSchema = ICFSecSchema.getBackingCFSec();
		if (targetBackingSchema == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredContainerCtry", 0, "ICFSecSchema.getBackingCFSec()");
		}
		ICFSecISOCtryTable targetTable = targetBackingSchema.getTableISOCtry();
		if (targetTable == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredContainerCtry", 0, "ICFSecSchema.getBackingCFSec().getTableISOCtry()");
		}
		ICFSecISOCtry targetRec = targetTable.readDerivedByIdIdx(ICFSecSchema.getAuthorizationCallback().getEffectiveAuthorization(), argISOCtryId);
		setRequiredContainerCtry(targetRec);
	}

	@Override
	public ICFSecISOLang getRequiredParentLang() {
		return(requiredParentLang);
	}

	@Override
	public void setRequiredParentLang(ICFSecISOLang argObj) {
		if(argObj == null) {
			throw new CFLibNullArgumentException(getClass(), "setParentLang", 1, "argObj");
		}
		else if (argObj instanceof CFSecJpaISOLang) {
			requiredParentLang = (CFSecJpaISOLang)argObj;
			if (requiredParentLang != null) {
				getPKey().setRequiredISOLangId(requiredParentLang.getRequiredISOLangId());
			}
			else {
			}
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "setParentLang", "argObj", argObj, "CFSecJpaISOLang");
		}
	
	}

	@Override
	public void setRequiredParentLang(ICFSecProtISOLang argObj) {
		setRequiredParentLang(argObj.getRequiredISOLangId());
	}

	@Override
	public void setRequiredParentLang(ICFSecPubISOLang argObj) {
		setRequiredParentLang(argObj.getRequiredISOLangId());
	}

	@Override
	public void setRequiredParentLang($implIJavaAtomType$ argISOLangId) {
		ICFSecSchema targetBackingSchema = ICFSecSchema.getBackingCFSec();
		if (targetBackingSchema == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredParentLang", 0, "ICFSecSchema.getBackingCFSec()");
		}
		ICFSecISOLangTable targetTable = targetBackingSchema.getTableISOLang();
		if (targetTable == null) {
			throw new CFLibNullArgumentException(getClass(), "setRequiredParentLang", 0, "ICFSecSchema.getBackingCFSec().getTableISOLang()");
		}
		ICFSecISOLang targetRec = targetTable.readDerivedByIdIdx(ICFSecSchema.getAuthorizationCallback().getEffectiveAuthorization(), argISOLangId);
		setRequiredParentLang(targetRec);
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
	public ICFSecISOCtryLangPKey getPKey() {
		return pkey;
	}

	@Override
	public void setPKey(ICFSecISOCtryLangPKey pkey ) {
		if (pkey == null) {
			throw new CFLibNullArgumentException(getClass(), "setPKey", 1, "pkey");
		}
		else if (!(pkey instanceof CFSecJpaISOCtryLangPKey)) {
			throw new CFLibUnsupportedClassException(getClass(), "setPKey", "pkey", pkey, "CFSecJpaISOCtryLangPKey");
		}
		this.pkey = (CFSecJpaISOCtryLangPKey)pkey;
	}

	@Override
	public $implIJavaAtomType$ getRequiredISOCtryId() {
		return( pkey.getRequiredISOCtryId() );
	}

	@Override
	public void setRequiredISOCtryId( $implIJavaAtomType$ requiredISOCtryId ) {
		pkey.setRequiredISOCtryId( requiredISOCtryId );
	}

	@Override
	public $implIJavaAtomType$ getRequiredISOLangId() {
		return( pkey.getRequiredISOLangId() );
	}

	@Override
	public void setRequiredISOLangId( $implIJavaAtomType$ requiredISOLangId ) {
		pkey.setRequiredISOLangId( requiredISOLangId );
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
		else if (obj instanceof ICFSecISOCtryLang) {
			ICFSecISOCtryLang rhs = (ICFSecISOCtryLang)obj;
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
			if( getRequiredISOCtryId() != rhs.getRequiredISOCtryId() ) {
				return( false );
			}
			if( getRequiredISOLangId() != rhs.getRequiredISOLangId() ) {
				return( false );
			}
			return( true );
		}
		else if (obj instanceof ICFSecISOCtryLangH) {
			ICFSecISOCtryLangH rhs = (ICFSecISOCtryLangH)obj;
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
			if( getRequiredISOCtryId() != rhs.getRequiredISOCtryId() ) {
				return( false );
			}
			if( getRequiredISOLangId() != rhs.getRequiredISOLangId() ) {
				return( false );
			}
			return( true );
		}
		else if (obj instanceof ICFSecISOCtryLangHPKey) {
			ICFSecISOCtryLangHPKey rhs = (ICFSecISOCtryLangHPKey)obj;
			if( getRequiredISOCtryId() != rhs.getRequiredISOCtryId() ) {
				return( false );
			}
			if( getRequiredISOLangId() != rhs.getRequiredISOLangId() ) {
				return( false );
			}
			return( true );
		}
		else if (obj instanceof ICFSecISOCtryLangByCtryIdxKey) {
			ICFSecISOCtryLangByCtryIdxKey rhs = (ICFSecISOCtryLangByCtryIdxKey)obj;
			if( getRequiredISOCtryId() != rhs.getRequiredISOCtryId() ) {
				return( false );
			}
			return( true );
		}
		else if (obj instanceof ICFSecISOCtryLangByLangIdxKey) {
			ICFSecISOCtryLangByLangIdxKey rhs = (ICFSecISOCtryLangByLangIdxKey)obj;
			if( getRequiredISOLangId() != rhs.getRequiredISOLangId() ) {
				return( false );
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
		hashCode = ( hashCode * 0x10000 ) + getRequiredISOCtryId();
		hashCode = ( hashCode * 0x10000 ) + getRequiredISOLangId();
		return( hashCode & 0x7fffffff );
	}

	@Override
	public int compareTo( Object obj ) {
		int cmp;
		if (obj == null) {
			return( 1 );
		}
		else if (obj instanceof ICFSecISOCtryLang) {
			ICFSecISOCtryLang rhs = (ICFSecISOCtryLang)obj;
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
		else if (obj instanceof ICFSecISOCtryLangHPKey) {
			ICFSecISOCtryLangHPKey rhs = (ICFSecISOCtryLangHPKey)obj;
			if( getRequiredISOCtryId() < rhs.getRequiredISOCtryId() ) {
				return( -1 );
			}
			else if( getRequiredISOCtryId() > rhs.getRequiredISOCtryId() ) {
				return( 1 );
			}
			if( getRequiredISOLangId() < rhs.getRequiredISOLangId() ) {
				return( -1 );
			}
			else if( getRequiredISOLangId() > rhs.getRequiredISOLangId() ) {
				return( 1 );
			}
			return( 0 );
		}
		else if( obj instanceof ICFSecISOCtryLangH ) {
			ICFSecISOCtryLangH rhs = (ICFSecISOCtryLangH)obj;
			if( getRequiredISOCtryId() < rhs.getRequiredISOCtryId() ) {
				return( -1 );
			}
			else if( getRequiredISOCtryId() > rhs.getRequiredISOCtryId() ) {
				return( 1 );
			}
			if( getRequiredISOLangId() < rhs.getRequiredISOLangId() ) {
				return( -1 );
			}
			else if( getRequiredISOLangId() > rhs.getRequiredISOLangId() ) {
				return( 1 );
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
		else if (obj instanceof ICFSecISOCtryLangByCtryIdxKey) {
			ICFSecISOCtryLangByCtryIdxKey rhs = (ICFSecISOCtryLangByCtryIdxKey)obj;
			if( getRequiredISOCtryId() < rhs.getRequiredISOCtryId() ) {
				return( -1 );
			}
			else if( getRequiredISOCtryId() > rhs.getRequiredISOCtryId() ) {
				return( 1 );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecISOCtryLangByLangIdxKey) {
			ICFSecISOCtryLangByLangIdxKey rhs = (ICFSecISOCtryLangByLangIdxKey)obj;
			if( getRequiredISOLangId() < rhs.getRequiredISOLangId() ) {
				return( -1 );
			}
			else if( getRequiredISOLangId() > rhs.getRequiredISOLangId() ) {
				return( 1 );
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
	public void set( ICFSecISOCtryLang src ) {
		setISOCtryLang( src );
	}

	@Override
	public void setISOCtryLang( ICFSecISOCtryLang src ) {
		setRequiredContainerCtry(src.getRequiredContainerCtry());
		setRequiredParentLang(src.getRequiredParentLang());
		setRequiredISOCtryId(src.getRequiredISOCtryId());
		setRequiredISOLangId(src.getRequiredISOLangId());
		setRequiredRevision( src.getRequiredRevision() );
		setCreatedByUserId( src.getCreatedByUserId() );
		setCreatedAt( src.getCreatedAt() );
		setUpdatedByUserId( src.getUpdatedByUserId() );
		setUpdatedAt( src.getUpdatedAt() );
	}

	@Override
	public void set( ICFSecISOCtryLangH src ) {
		setISOCtryLang( src );
	}

	@Override
	public void setISOCtryLang( ICFSecISOCtryLangH src ) {
		setRequiredContainerCtry(src.getRequiredISOCtryId());
		setRequiredParentLang(src.getRequiredISOLangId());
		setRequiredISOCtryId(src.getRequiredISOCtryId());
		setRequiredISOLangId(src.getRequiredISOLangId());
	}

	@Override
	public String getXmlAttrFragment() {
		String ret = pkey.getXmlAttrFragment() 
			+ " RequiredRevision=\"" + Integer.toString( getRequiredRevision() ) + "\""
			+ " RequiredISOCtryId=" + "\"" + Short.toString( getRequiredISOCtryId() ) + "\""
			+ " RequiredISOLangId=" + "\"" + Short.toString( getRequiredISOLangId() ) + "\"";
		return( ret );
	}

	@Override
	public String toString() {
		String ret = "<CFSecJpaISOCtryLang" + getXmlAttrFragment() + "/>";
		return( ret );
	}
}
