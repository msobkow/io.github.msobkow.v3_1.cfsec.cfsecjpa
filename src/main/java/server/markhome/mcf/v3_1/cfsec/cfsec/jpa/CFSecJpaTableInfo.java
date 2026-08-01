// Description: Java 25 JPA implementation of a TableInfo entity definition object.

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
	name = "table_info", schema = "CFSec31",
	indexes = {
		@Index(name = "TableInfoIdIdx", columnList = "TableInfoId", unique = true),
		@Index(name = "TableInfoTableNameIdx", columnList = "tbl_name", unique = true),
		@Index(name = "TableInfoSuperNameIdx", columnList = "sup_name", unique = false),
		@Index(name = "TableInfoSchemaNameIdx", columnList = "sch_name", unique = false),
		@Index(name = "TableInfoSchemaBkCodeIdx", columnList = "sch_name, back_clscode", unique = true),
		@Index(name = "TableInfoSchemaRTCodeIdx", columnList = "runtm_clscode", unique = true),
		@Index(name = "TableInfoSuperNameIdxSuperRef", columnList = "sup_nameSuperRef", unique = false)
	}
)
@Transactional(Transactional.TxType.SUPPORTS)
@PersistenceContext(unitName = "CFSecPU")
public class CFSecJpaTableInfo
	implements Comparable<Object>,
		ICFSecTableInfo,
		Serializable
{
	@Id
	@GeneratedValue(strategy=GenerationType.SEQUENCE, generator="cfsec_tblinfoidgenseq")
	@SequenceGenerator(name = "cfsec_tblinfoidgenseq", allocationSize = 1, initialValue = 0, schema = "CFSec31")
	@Column( name="TableInfoId", nullable=false )
	protected int requiredTableInfoId;
	protected int requiredRevision;

	@ManyToOne(fetch=FetchType.LAZY, optional=true)
	@JoinColumn( name="sup_nameSuperRef", referencedColumnName="tbl_name" )
	protected CFSecJpaTableInfo optionalParentSuperRef;
	@OneToMany(fetch=FetchType.LAZY, mappedBy="optionalParentSuperRef")
	protected Set<CFSecJpaTableInfo> optionalChildrenSubRefs;

	@Column( name="sch_name", nullable=false, length=32 )
	protected String requiredSchemaName;
	@Column( name="tbl_name", nullable=false, length=64 )
	protected String requiredTableName;
	@Column( name="sup_name", nullable=true, length=64 )
	protected String optionalSuperName;
	@Column( name="back_clscode", nullable=false )
	protected int requiredBackingClassCode;
	@Column( name="runtm_clscode", nullable=false )
	protected int requiredRuntimeClassCode;
	@Column( name="has_hist", nullable=false )
	protected boolean requiredHasHistory;
	@Column( name="is_mutable", nullable=false )
	protected boolean requiredIsMutable;
	@Column( name="sec_scope_name", nullable=false, length=32 )
	protected String requiredSecScopeName;
	@Column( name="cd_vis", nullable=false, length=32 )
	protected String requiredCodeVis;

	public CFSecJpaTableInfo() {
		requiredTableInfoId = ICFSecTableInfo.TABLEINFOID_INIT_VALUE;
		requiredSchemaName = ICFSecTableInfo.SCHEMANAME_INIT_VALUE;
		requiredTableName = ICFSecTableInfo.TABLENAME_INIT_VALUE;
		optionalSuperName = null;
		requiredBackingClassCode = ICFSecTableInfo.BACKINGCLASSCODE_INIT_VALUE;
		requiredRuntimeClassCode = ICFSecTableInfo.RUNTIMECLASSCODE_INIT_VALUE;
		requiredHasHistory = ICFSecTableInfo.HASHISTORY_INIT_VALUE;
		requiredIsMutable = ICFSecTableInfo.ISMUTABLE_INIT_VALUE;
		requiredSecScopeName = ICFSecTableInfo.SECSCOPENAME_INIT_VALUE;
		requiredCodeVis = ICFSecTableInfo.CODEVIS_INIT_VALUE;
	}

	@Override
	public int getClassCode() {
		return( ICFSecTableInfo.CLASS_CODE );
	}

	@Override
	public ICFSecTableInfo getOptionalParentSuperRef() {
		return(optionalParentSuperRef);
	}

	@Override
	public void setOptionalParentSuperRef(ICFSecTableInfo argObj) {
		if(argObj == null) {
			optionalParentSuperRef = null;
		}
		else if (argObj instanceof CFSecJpaTableInfo) {
			optionalParentSuperRef = (CFSecJpaTableInfo)argObj;
			if (optionalParentSuperRef != null) {
				optionalSuperName = optionalParentSuperRef.getRequiredTableName();
			}
			else {
				optionalSuperName = null;
			}
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "setParentSuperRef", "argObj", argObj, "CFSecJpaTableInfo");
		}
	}

	@Override
	public void setOptionalParentSuperRef(ICFSecProtTableInfo argObj) {
		setOptionalParentSuperRef(argObj.getRequiredTableName());
	}

	@Override
	public void setOptionalParentSuperRef(ICFSecPubTableInfo argObj) {
		setOptionalParentSuperRef(argObj.getRequiredTableName());
	}

	@Override
	public void setOptionalParentSuperRef(String argSuperName) {
		ICFSecSchema targetBackingSchema = ICFSecSchema.getBackingCFSec();
		if (targetBackingSchema == null) {
			throw new CFLibNullArgumentException(getClass(), "setOptionalParentSuperRef", 0, "ICFSecSchema.getBackingCFSec()");
		}
		ICFSecTableInfoTable targetTable = targetBackingSchema.getTableTableInfo();
		if (targetTable == null) {
			throw new CFLibNullArgumentException(getClass(), "setOptionalParentSuperRef", 0, "ICFSecSchema.getBackingCFSec().getTableTableInfo()");
		}
		ICFSecTableInfo targetRec = targetTable.readDerivedByTableNameIdx(ICFSecSchema.getAuthorizationCallback().getEffectiveAuthorization(), argSuperName);
		setOptionalParentSuperRef(targetRec);
	}

	@Override
	public List<ICFSecTableInfo> getOptionalChildrenSubRefs() {
		List<ICFSecTableInfo> retlist = (optionalChildrenSubRefs != null) ? new ArrayList<>(optionalChildrenSubRefs) : new ArrayList<>();
		return( retlist );
	}

	@Override
	public Integer getPKey() {
		return getRequiredTableInfoId();
	}

	@Override
	public void setPKey(Integer requiredTableInfoId) {
		this.requiredTableInfoId = requiredTableInfoId;
	}

	@Override
	public int getRequiredTableInfoId() {
		return( getPKey() );
	}

	@Override
	public void setRequiredTableInfoId( int value ) {
		if( value < ICFSecTableInfo.TABLEINFOID_MIN_VALUE ) {
			throw new CFLibArgumentUnderflowException( getClass(),
				"setRequiredTableInfoId",
				1,
				"value",
				value,
				ICFSecTableInfo.TABLEINFOID_MIN_VALUE );
		}
		setPKey( value );
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
	public String getRequiredSchemaName() {
		return( requiredSchemaName );
	}

	public void setRequiredSchemaName( String value ) {
		if( value == null ) {
			throw new CFLibNullArgumentException( getClass(),
				"setRequiredSchemaName",
				1,
				"value" );
		}
		else if( value.length() > 32 ) {
			throw new CFLibArgumentOverflowException( getClass(),
				"setRequiredSchemaName",
				1,
				"value.length()",
				value.length(),
				32 );
		}
		requiredSchemaName = value;
	}

	@Override
	public String getRequiredTableName() {
		return( requiredTableName );
	}

	public void setRequiredTableName( String value ) {
		if( value == null ) {
			throw new CFLibNullArgumentException( getClass(),
				"setRequiredTableName",
				1,
				"value" );
		}
		else if( value.length() > 64 ) {
			throw new CFLibArgumentOverflowException( getClass(),
				"setRequiredTableName",
				1,
				"value.length()",
				value.length(),
				64 );
		}
		requiredTableName = value;
	}

	@Override
	public String getOptionalSuperName() {
		return( optionalSuperName );
	}

	public void setOptionalSuperName( String value ) {
		if( value != null && value.length() > 64 ) {
			throw new CFLibArgumentOverflowException( getClass(),
				"setOptionalSuperName",
				1,
				"value.length()",
				value.length(),
				64 );
		}
		optionalSuperName = value;
	}

	@Override
	public int getRequiredBackingClassCode() {
		return( requiredBackingClassCode );
	}

	@Override
	public void setRequiredBackingClassCode( int value ) {
		if( value < ICFSecTableInfo.BACKINGCLASSCODE_MIN_VALUE ) {
			throw new CFLibArgumentUnderflowException( getClass(),
				"setRequiredBackingClassCode",
				1,
				"value",
				value,
				ICFSecTableInfo.BACKINGCLASSCODE_MIN_VALUE );
		}
		requiredBackingClassCode = value;
	}

	@Override
	public int getRequiredRuntimeClassCode() {
		return( requiredRuntimeClassCode );
	}

	@Override
	public void setRequiredRuntimeClassCode( int value ) {
		if( value < ICFSecTableInfo.RUNTIMECLASSCODE_MIN_VALUE ) {
			throw new CFLibArgumentUnderflowException( getClass(),
				"setRequiredRuntimeClassCode",
				1,
				"value",
				value,
				ICFSecTableInfo.RUNTIMECLASSCODE_MIN_VALUE );
		}
		requiredRuntimeClassCode = value;
	}

	@Override
	public boolean getRequiredHasHistory() {
		return( requiredHasHistory );
	}

	public void setRequiredHasHistory( boolean value ) {
		requiredHasHistory = value;
	}

	@Override
	public boolean getRequiredIsMutable() {
		return( requiredIsMutable );
	}

	public void setRequiredIsMutable( boolean value ) {
		requiredIsMutable = value;
	}

	@Override
	public String getRequiredSecScopeName() {
		return( requiredSecScopeName );
	}

	public void setRequiredSecScopeName( String value ) {
		if( value == null ) {
			throw new CFLibNullArgumentException( getClass(),
				"setRequiredSecScopeName",
				1,
				"value" );
		}
		else if( value.length() > 32 ) {
			throw new CFLibArgumentOverflowException( getClass(),
				"setRequiredSecScopeName",
				1,
				"value.length()",
				value.length(),
				32 );
		}
		requiredSecScopeName = value;
	}

	@Override
	public String getRequiredCodeVis() {
		return( requiredCodeVis );
	}

	public void setRequiredCodeVis( String value ) {
		if( value == null ) {
			throw new CFLibNullArgumentException( getClass(),
				"setRequiredCodeVis",
				1,
				"value" );
		}
		else if( value.length() > 32 ) {
			throw new CFLibArgumentOverflowException( getClass(),
				"setRequiredCodeVis",
				1,
				"value.length()",
				value.length(),
				32 );
		}
		requiredCodeVis = value;
	}

	@Override
	public boolean equals( Object obj ) {
		if (obj == null) {
			return( false );
		}
		else if (obj instanceof ICFSecTableInfo) {
			ICFSecTableInfo rhs = (ICFSecTableInfo)obj;
			if( getRequiredTableInfoId() != rhs.getRequiredTableInfoId() ) {
				return( false );
			}
			if( getRequiredSchemaName() != null ) {
				if( rhs.getRequiredSchemaName() != null ) {
					if( ! getRequiredSchemaName().equals( rhs.getRequiredSchemaName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSchemaName() != null ) {
					return( false );
				}
			}
			if( getRequiredTableName() != null ) {
				if( rhs.getRequiredTableName() != null ) {
					if( ! getRequiredTableName().equals( rhs.getRequiredTableName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredTableName() != null ) {
					return( false );
				}
			}
			if( getOptionalSuperName() != null ) {
				if( rhs.getOptionalSuperName() != null ) {
					if( ! getOptionalSuperName().equals( rhs.getOptionalSuperName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getOptionalSuperName() != null ) {
					return( false );
				}
			}
			if( getRequiredBackingClassCode() != rhs.getRequiredBackingClassCode() ) {
				return( false );
			}
			if( getRequiredRuntimeClassCode() != rhs.getRequiredRuntimeClassCode() ) {
				return( false );
			}
			if( getRequiredHasHistory() != rhs.getRequiredHasHistory() ) {
				return( false );
			}
			if( getRequiredIsMutable() != rhs.getRequiredIsMutable() ) {
				return( false );
			}
			if( getRequiredSecScopeName() != null ) {
				if( rhs.getRequiredSecScopeName() != null ) {
					if( ! getRequiredSecScopeName().equals( rhs.getRequiredSecScopeName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecScopeName() != null ) {
					return( false );
				}
			}
			if( getRequiredCodeVis() != null ) {
				if( rhs.getRequiredCodeVis() != null ) {
					if( ! getRequiredCodeVis().equals( rhs.getRequiredCodeVis() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredCodeVis() != null ) {
					return( false );
				}
			}
			return( true );
		}
		else if (obj instanceof ICFSecTableInfoH) {
			ICFSecTableInfoH rhs = (ICFSecTableInfoH)obj;
			if( getRequiredTableInfoId() != rhs.getRequiredTableInfoId() ) {
				return( false );
			}
			if( getRequiredSchemaName() != null ) {
				if( rhs.getRequiredSchemaName() != null ) {
					if( ! getRequiredSchemaName().equals( rhs.getRequiredSchemaName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSchemaName() != null ) {
					return( false );
				}
			}
			if( getRequiredTableName() != null ) {
				if( rhs.getRequiredTableName() != null ) {
					if( ! getRequiredTableName().equals( rhs.getRequiredTableName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredTableName() != null ) {
					return( false );
				}
			}
			if( getOptionalSuperName() != null ) {
				if( rhs.getOptionalSuperName() != null ) {
					if( ! getOptionalSuperName().equals( rhs.getOptionalSuperName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getOptionalSuperName() != null ) {
					return( false );
				}
			}
			if( getRequiredBackingClassCode() != rhs.getRequiredBackingClassCode() ) {
				return( false );
			}
			if( getRequiredRuntimeClassCode() != rhs.getRequiredRuntimeClassCode() ) {
				return( false );
			}
			if( getRequiredHasHistory() != rhs.getRequiredHasHistory() ) {
				return( false );
			}
			if( getRequiredIsMutable() != rhs.getRequiredIsMutable() ) {
				return( false );
			}
			if( getRequiredSecScopeName() != null ) {
				if( rhs.getRequiredSecScopeName() != null ) {
					if( ! getRequiredSecScopeName().equals( rhs.getRequiredSecScopeName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecScopeName() != null ) {
					return( false );
				}
			}
			if( getRequiredCodeVis() != null ) {
				if( rhs.getRequiredCodeVis() != null ) {
					if( ! getRequiredCodeVis().equals( rhs.getRequiredCodeVis() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredCodeVis() != null ) {
					return( false );
				}
			}
			return( true );
		}
		else if (obj instanceof ICFSecTableInfoHPKey) {
			ICFSecTableInfoHPKey rhs = (ICFSecTableInfoHPKey)obj;
			if( getRequiredTableInfoId() != rhs.getRequiredTableInfoId() ) {
				return( false );
			}
			return( true );
		}
		else if (obj instanceof ICFSecTableInfoByTableNameIdxKey) {
			ICFSecTableInfoByTableNameIdxKey rhs = (ICFSecTableInfoByTableNameIdxKey)obj;
			if( getRequiredTableName() != null ) {
				if( rhs.getRequiredTableName() != null ) {
					if( ! getRequiredTableName().equals( rhs.getRequiredTableName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredTableName() != null ) {
					return( false );
				}
			}
			return( true );
		}
		else if (obj instanceof ICFSecTableInfoBySuperNameIdxKey) {
			ICFSecTableInfoBySuperNameIdxKey rhs = (ICFSecTableInfoBySuperNameIdxKey)obj;
			if( getOptionalSuperName() != null ) {
				if( rhs.getOptionalSuperName() != null ) {
					if( ! getOptionalSuperName().equals( rhs.getOptionalSuperName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getOptionalSuperName() != null ) {
					return( false );
				}
			}
			return( true );
		}
		else if (obj instanceof ICFSecTableInfoBySchemaNameIdxKey) {
			ICFSecTableInfoBySchemaNameIdxKey rhs = (ICFSecTableInfoBySchemaNameIdxKey)obj;
			if( getRequiredSchemaName() != null ) {
				if( rhs.getRequiredSchemaName() != null ) {
					if( ! getRequiredSchemaName().equals( rhs.getRequiredSchemaName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSchemaName() != null ) {
					return( false );
				}
			}
			return( true );
		}
		else if (obj instanceof ICFSecTableInfoBySchemaBkCodeIdxKey) {
			ICFSecTableInfoBySchemaBkCodeIdxKey rhs = (ICFSecTableInfoBySchemaBkCodeIdxKey)obj;
			if( getRequiredSchemaName() != null ) {
				if( rhs.getRequiredSchemaName() != null ) {
					if( ! getRequiredSchemaName().equals( rhs.getRequiredSchemaName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSchemaName() != null ) {
					return( false );
				}
			}
			if( getRequiredBackingClassCode() != rhs.getRequiredBackingClassCode() ) {
				return( false );
			}
			return( true );
		}
		else if (obj instanceof ICFSecTableInfoBySchemaRTCodeIdxKey) {
			ICFSecTableInfoBySchemaRTCodeIdxKey rhs = (ICFSecTableInfoBySchemaRTCodeIdxKey)obj;
			if( getRequiredRuntimeClassCode() != rhs.getRequiredRuntimeClassCode() ) {
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
		hashCode = hashCode + getRequiredTableInfoId();
		if( getRequiredSchemaName() != null ) {
			hashCode = hashCode + getRequiredSchemaName().hashCode();
		}
		if( getRequiredTableName() != null ) {
			hashCode = hashCode + getRequiredTableName().hashCode();
		}
		if( getOptionalSuperName() != null ) {
			hashCode = hashCode + getOptionalSuperName().hashCode();
		}
		hashCode = hashCode + getRequiredBackingClassCode();
		hashCode = hashCode + getRequiredRuntimeClassCode();
		if( getRequiredHasHistory() ) {
			hashCode = ( hashCode * 2 ) + 1;
		}
		else {
			hashCode = hashCode * 2;
		}
		if( getRequiredIsMutable() ) {
			hashCode = ( hashCode * 2 ) + 1;
		}
		else {
			hashCode = hashCode * 2;
		}
		if( getRequiredSecScopeName() != null ) {
			hashCode = hashCode + getRequiredSecScopeName().hashCode();
		}
		if( getRequiredCodeVis() != null ) {
			hashCode = hashCode + getRequiredCodeVis().hashCode();
		}
		return( hashCode & 0x7fffffff );
	}

	@Override
	public int compareTo( Object obj ) {
		int cmp;
		if (obj == null) {
			return( 1 );
		}
		else if (obj instanceof ICFSecTableInfo) {
			ICFSecTableInfo rhs = (ICFSecTableInfo)obj;
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
			if (getRequiredSchemaName() != null) {
				if (rhs.getRequiredSchemaName() != null) {
					cmp = getRequiredSchemaName().compareTo( rhs.getRequiredSchemaName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSchemaName() != null) {
				return( -1 );
			}
			if (getRequiredTableName() != null) {
				if (rhs.getRequiredTableName() != null) {
					cmp = getRequiredTableName().compareTo( rhs.getRequiredTableName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredTableName() != null) {
				return( -1 );
			}
			if( getOptionalSuperName() != null ) {
				if( rhs.getOptionalSuperName() != null ) {
					cmp = getOptionalSuperName().compareTo( rhs.getOptionalSuperName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else {
				if( rhs.getOptionalSuperName() != null ) {
					return( -1 );
				}
			}
			if( getRequiredBackingClassCode() < rhs.getRequiredBackingClassCode() ) {
				return( -1 );
			}
			else if( getRequiredBackingClassCode() > rhs.getRequiredBackingClassCode() ) {
				return( 1 );
			}
			if( getRequiredRuntimeClassCode() < rhs.getRequiredRuntimeClassCode() ) {
				return( -1 );
			}
			else if( getRequiredRuntimeClassCode() > rhs.getRequiredRuntimeClassCode() ) {
				return( 1 );
			}
			if( getRequiredHasHistory() ) {
				if( ! rhs.getRequiredHasHistory() ) {
					return( 1 );
				}
			}
			else {
				if( rhs.getRequiredHasHistory() ) {
					return( -1 );
				}
			}
			if( getRequiredIsMutable() ) {
				if( ! rhs.getRequiredIsMutable() ) {
					return( 1 );
				}
			}
			else {
				if( rhs.getRequiredIsMutable() ) {
					return( -1 );
				}
			}
			if (getRequiredSecScopeName() != null) {
				if (rhs.getRequiredSecScopeName() != null) {
					cmp = getRequiredSecScopeName().compareTo( rhs.getRequiredSecScopeName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecScopeName() != null) {
				return( -1 );
			}
			if (getRequiredCodeVis() != null) {
				if (rhs.getRequiredCodeVis() != null) {
					cmp = getRequiredCodeVis().compareTo( rhs.getRequiredCodeVis() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredCodeVis() != null) {
				return( -1 );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecTableInfoHPKey) {
			ICFSecTableInfoHPKey rhs = (ICFSecTableInfoHPKey)obj;
			if( getRequiredTableInfoId() < rhs.getRequiredTableInfoId() ) {
				return( -1 );
			}
			else if( getRequiredTableInfoId() > rhs.getRequiredTableInfoId() ) {
				return( 1 );
			}
			return( 0 );
		}
		else if( obj instanceof ICFSecTableInfoH ) {
			ICFSecTableInfoH rhs = (ICFSecTableInfoH)obj;
			if( getRequiredTableInfoId() < rhs.getRequiredTableInfoId() ) {
				return( -1 );
			}
			else if( getRequiredTableInfoId() > rhs.getRequiredTableInfoId() ) {
				return( 1 );
			}
			if (getRequiredSchemaName() != null) {
				if (rhs.getRequiredSchemaName() != null) {
					cmp = getRequiredSchemaName().compareTo( rhs.getRequiredSchemaName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSchemaName() != null) {
				return( -1 );
			}
			if (getRequiredTableName() != null) {
				if (rhs.getRequiredTableName() != null) {
					cmp = getRequiredTableName().compareTo( rhs.getRequiredTableName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredTableName() != null) {
				return( -1 );
			}
			if( getOptionalSuperName() != null ) {
				if( rhs.getOptionalSuperName() != null ) {
					cmp = getOptionalSuperName().compareTo( rhs.getOptionalSuperName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else {
				if( rhs.getOptionalSuperName() != null ) {
					return( -1 );
				}
			}
			if( getRequiredBackingClassCode() < rhs.getRequiredBackingClassCode() ) {
				return( -1 );
			}
			else if( getRequiredBackingClassCode() > rhs.getRequiredBackingClassCode() ) {
				return( 1 );
			}
			if( getRequiredRuntimeClassCode() < rhs.getRequiredRuntimeClassCode() ) {
				return( -1 );
			}
			else if( getRequiredRuntimeClassCode() > rhs.getRequiredRuntimeClassCode() ) {
				return( 1 );
			}
			if( getRequiredHasHistory() ) {
				if( ! rhs.getRequiredHasHistory() ) {
					return( 1 );
				}
			}
			else {
				if( rhs.getRequiredHasHistory() ) {
					return( -1 );
				}
			}
			if( getRequiredIsMutable() ) {
				if( ! rhs.getRequiredIsMutable() ) {
					return( 1 );
				}
			}
			else {
				if( rhs.getRequiredIsMutable() ) {
					return( -1 );
				}
			}
			if (getRequiredSecScopeName() != null) {
				if (rhs.getRequiredSecScopeName() != null) {
					cmp = getRequiredSecScopeName().compareTo( rhs.getRequiredSecScopeName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecScopeName() != null) {
				return( -1 );
			}
			if (getRequiredCodeVis() != null) {
				if (rhs.getRequiredCodeVis() != null) {
					cmp = getRequiredCodeVis().compareTo( rhs.getRequiredCodeVis() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredCodeVis() != null) {
				return( -1 );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecTableInfoByTableNameIdxKey) {
			ICFSecTableInfoByTableNameIdxKey rhs = (ICFSecTableInfoByTableNameIdxKey)obj;
			if (getRequiredTableName() != null) {
				if (rhs.getRequiredTableName() != null) {
					cmp = getRequiredTableName().compareTo( rhs.getRequiredTableName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredTableName() != null) {
				return( -1 );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecTableInfoBySuperNameIdxKey) {
			ICFSecTableInfoBySuperNameIdxKey rhs = (ICFSecTableInfoBySuperNameIdxKey)obj;
			if( getOptionalSuperName() != null ) {
				if( rhs.getOptionalSuperName() != null ) {
					cmp = getOptionalSuperName().compareTo( rhs.getOptionalSuperName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else {
				if( rhs.getOptionalSuperName() != null ) {
					return( -1 );
				}
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecTableInfoBySchemaNameIdxKey) {
			ICFSecTableInfoBySchemaNameIdxKey rhs = (ICFSecTableInfoBySchemaNameIdxKey)obj;
			if (getRequiredSchemaName() != null) {
				if (rhs.getRequiredSchemaName() != null) {
					cmp = getRequiredSchemaName().compareTo( rhs.getRequiredSchemaName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSchemaName() != null) {
				return( -1 );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecTableInfoBySchemaBkCodeIdxKey) {
			ICFSecTableInfoBySchemaBkCodeIdxKey rhs = (ICFSecTableInfoBySchemaBkCodeIdxKey)obj;
			if (getRequiredSchemaName() != null) {
				if (rhs.getRequiredSchemaName() != null) {
					cmp = getRequiredSchemaName().compareTo( rhs.getRequiredSchemaName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSchemaName() != null) {
				return( -1 );
			}
			if( getRequiredBackingClassCode() < rhs.getRequiredBackingClassCode() ) {
				return( -1 );
			}
			else if( getRequiredBackingClassCode() > rhs.getRequiredBackingClassCode() ) {
				return( 1 );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecTableInfoBySchemaRTCodeIdxKey) {
			ICFSecTableInfoBySchemaRTCodeIdxKey rhs = (ICFSecTableInfoBySchemaRTCodeIdxKey)obj;
			if( getRequiredRuntimeClassCode() < rhs.getRequiredRuntimeClassCode() ) {
				return( -1 );
			}
			else if( getRequiredRuntimeClassCode() > rhs.getRequiredRuntimeClassCode() ) {
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
	public void set( ICFSecTableInfo src ) {
		setTableInfo( src );
	}

	@Override
	public void setTableInfo( ICFSecTableInfo src ) {
		setRequiredTableInfoId(src.getRequiredTableInfoId());
		setRequiredRevision( src.getRequiredRevision() );
		setOptionalParentSuperRef(src.getOptionalParentSuperRef());
		setRequiredSchemaName(src.getRequiredSchemaName());
		setRequiredTableName(src.getRequiredTableName());
		setRequiredBackingClassCode(src.getRequiredBackingClassCode());
		setRequiredRuntimeClassCode(src.getRequiredRuntimeClassCode());
		setRequiredHasHistory(src.getRequiredHasHistory());
		setRequiredIsMutable(src.getRequiredIsMutable());
		setRequiredSecScopeName(src.getRequiredSecScopeName());
		setRequiredCodeVis(src.getRequiredCodeVis());
	}

	@Override
	public void set( ICFSecTableInfoH src ) {
		setTableInfo( src );
	}

	@Override
	public void setTableInfo( ICFSecTableInfoH src ) {
		setRequiredTableInfoId(src.getRequiredTableInfoId());
		setOptionalParentSuperRef(src.getOptionalSuperName());
		setRequiredSchemaName(src.getRequiredSchemaName());
		setRequiredTableName(src.getRequiredTableName());
		setRequiredBackingClassCode(src.getRequiredBackingClassCode());
		setRequiredRuntimeClassCode(src.getRequiredRuntimeClassCode());
		setRequiredHasHistory(src.getRequiredHasHistory());
		setRequiredIsMutable(src.getRequiredIsMutable());
		setRequiredSecScopeName(src.getRequiredSecScopeName());
		setRequiredCodeVis(src.getRequiredCodeVis());
	}

	@Override
	public String getXmlAttrFragment() {
		String ret = ""
			+ " RequiredTableInfoId=" + "\"" + Integer.toString( getRequiredTableInfoId() ) + "\""
			+ " RequiredRevision=\"" + Integer.toString( getRequiredRevision() ) + "\""
			+ " RequiredTableInfoId=" + "\"" + Integer.toString( getRequiredTableInfoId() ) + "\""
			+ " RequiredSchemaName=" + "\"" + StringEscapeUtils.escapeXml11( getRequiredSchemaName() ) + "\""
			+ " RequiredTableName=" + "\"" + StringEscapeUtils.escapeXml11( getRequiredTableName() ) + "\""
			+ " OptionalSuperName=" + ( ( getOptionalSuperName() == null ) ? "null" : "\"" + StringEscapeUtils.escapeXml11( getOptionalSuperName() ) + "\"" )
			+ " RequiredBackingClassCode=" + "\"" + Integer.toString( getRequiredBackingClassCode() ) + "\""
			+ " RequiredRuntimeClassCode=" + "\"" + Integer.toString( getRequiredRuntimeClassCode() ) + "\""
			+ " RequiredHasHistory=" + (( getRequiredHasHistory() ) ? "\"true\"" : "\"false\"" )
			+ " RequiredIsMutable=" + (( getRequiredIsMutable() ) ? "\"true\"" : "\"false\"" )
			+ " RequiredSecScopeName=" + "\"" + StringEscapeUtils.escapeXml11( getRequiredSecScopeName() ) + "\""
			+ " RequiredCodeVis=" + "\"" + StringEscapeUtils.escapeXml11( getRequiredCodeVis() ) + "\"";
		return( ret );
	}

	@Override
	public String toString() {
		String ret = "<CFSecJpaTableInfo" + getXmlAttrFragment() + "/>";
		return( ret );
	}
}
