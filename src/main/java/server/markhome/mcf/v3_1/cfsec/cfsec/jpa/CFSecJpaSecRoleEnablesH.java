// Description: Java 25 JPA implementation of SecRoleEnables history objects

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
 *  CFSecJpaSecRoleEnablesH provides history objects matching the CFSecSecRoleEnables change history.
 */
@Entity
@Table(
    name = "SecRoleEnables_h", schema = "CFSec31",
    indexes = {
        @Index(name = "SecRoleEnablesIdIdx_h", columnList = "auditClusterId, auditStamp, auditAction, requiredRevision, auditSessionId, SecRoleId, enable_name", unique = true),
        @Index(name = "SecRoleEnablesRoleIdx_h", columnList = "SecRoleId", unique = false),
        @Index(name = "SecRoleEnableNameIdx_h", columnList = "enable_name", unique = false)
    }
)
@Transactional(Transactional.TxType.SUPPORTS)
@PersistenceContext(unitName = "CFSecPU")
public class CFSecJpaSecRoleEnablesH
    implements ICFSecSecRoleEnablesH, Comparable<Object>, Serializable
{
	@AttributeOverrides({
		@AttributeOverride(name="auditClusterId", column = @Column( name="auditClusterId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) ),
		@AttributeOverride(name="auditStamp", column = @Column( name="auditStamp", nullable=false ) ),
		@AttributeOverride(name="auditAction", column = @Column( name="auditAction", nullable=false ) ),
		@AttributeOverride(name="requiredRevision", column = @Column( name="requiredRevision", nullable=false ) ),
		@AttributeOverride(name="auditSessionId", column = @Column( name="auditSessionId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) ),
		@AttributeOverride(name="SecRoleId", column = @Column( name="SecRoleId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) ),
		@AttributeOverride(name="enable_name", column = @Column( name="enable_name", nullable=false, length=64 ) )
	})
    @EmbeddedId
    protected CFSecJpaSecRoleEnablesHPKey pkey;
	@AttributeOverrides({
		@AttributeOverride( name="bytes", column = @Column( name="CreatedByUserId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) )
	})
	protected CFLibDbKeyHash256 createdByUserId = CFLibDbKeyHash256.fromHex(ICFSecSecRoleEnables.S_INIT_CREATED_BY);

	@Column(name="CreatedAt", nullable=false)
	protected LocalDateTime createdAt = LocalDateTime.now();

	@AttributeOverrides({
		@AttributeOverride( name="bytes", column= @Column( name="UpdatedByUserId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) )
	})
	protected CFLibDbKeyHash256 updatedByUserId = CFLibDbKeyHash256.fromHex(ICFSecSecRoleEnables.S_INIT_UPDATED_BY);

	@Column(name="UpdatedAt", nullable=false)
	protected LocalDateTime updatedAt = LocalDateTime.now();

    public CFSecJpaSecRoleEnablesH() {
            // The primary key member attributes are initialized on construction
            pkey = new CFSecJpaSecRoleEnablesHPKey();
    }

    @Override
    public int getClassCode() {
            return( ICFSecSecRoleEnables.CLASS_CODE );
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
    public ICFSecSecRoleEnablesHPKey getPKey() {
        return( pkey );
    }

    @Override
    public void setPKey( ICFSecSecRoleEnablesHPKey pkey ) {
        if (pkey != null) {
            if (pkey instanceof CFSecJpaSecRoleEnablesHPKey) {
                this.pkey = (CFSecJpaSecRoleEnablesHPKey)pkey;
            }
            else {
                throw new CFLibUnsupportedClassException(getClass(), "setPKey", "pkey", pkey, "CFSecJpaSecRoleEnablesHPKey");
            }
        }
    }

    @Override
    public CFLibDbKeyHash256 getAuditClusterId() {
        return pkey.getAuditClusterId();
    }

    @Override
    public void setAuditClusterId(CFLibDbKeyHash256 auditClusterId) {
        pkey.setAuditClusterId(auditClusterId);
    }

    @Override
    public LocalDateTime getAuditStamp() {
        return pkey.getAuditStamp();
    }

    @Override
    public void setAuditStamp(LocalDateTime auditStamp) {
        pkey.setAuditStamp(auditStamp);
    }

    @Override
    public short getAuditActionId() {
        return pkey.getAuditActionId();
    }

    @Override
    public void setAuditActionId(short auditActionId) {
        pkey.setAuditActionId(auditActionId);
    }

    @Override
    public int getRequiredRevision() {
        return pkey.getRequiredRevision();
    }

    @Override
    public void setRequiredRevision(int revision) {
        pkey.setRequiredRevision(revision);
    }

    @Override
    public CFLibDbKeyHash256 getAuditSessionId() {
        return pkey.getAuditSessionId();
    }

    @Override
    public void setAuditSessionId(CFLibDbKeyHash256 auditSessionId) {
        pkey.setAuditSessionId(auditSessionId);
    }

    @Override
    public CFLibDbKeyHash256 getRequiredSecRoleId() {
        return( pkey.getRequiredSecRoleId() );
    }

    @Override
    public void setRequiredSecRoleId( CFLibDbKeyHash256 requiredSecRoleId ) {
        pkey.setRequiredSecRoleId( requiredSecRoleId );
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
    public boolean equals( Object obj ) {
        if (obj == null) {
            return( false );
        }
        else if (obj instanceof ICFSecSecRoleEnables) {
            ICFSecSecRoleEnables rhs = (ICFSecSecRoleEnables)obj;
		if (getPKey() != null) {
			if (rhs.getPKey() != null) {
				if (!getPKey().equals(rhs.getPKey())) {
					return( false );
				}
			}
			else {
				return( false );
			}
		}
		else if (rhs.getPKey() != null) {
			return( false );
		}

            return( true );
        }
        else if (obj instanceof ICFSecSecRoleEnablesH) {
            ICFSecSecRoleEnablesH rhs = (ICFSecSecRoleEnablesH)obj;
		if (getPKey() != null) {
			if (rhs.getPKey() != null) {
				if (!getPKey().equals(rhs.getPKey())) {
					return( false );
				}
			}
			else {
				return( false );
			}
		}
		else if (rhs.getPKey() != null) {
			return( false );
		}

            return( true );
        }
        else if (obj instanceof ICFSecSecRoleEnablesHPKey) {
		ICFSecSecRoleEnablesHPKey rhs = (ICFSecSecRoleEnablesHPKey)obj;
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
        else if (obj instanceof ICFSecSecRoleEnablesByRoleIdxKey) {
            ICFSecSecRoleEnablesByRoleIdxKey rhs = (ICFSecSecRoleEnablesByRoleIdxKey)obj;
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
            return( true );
        }
        else if (obj instanceof ICFSecSecRoleEnablesByNameIdxKey) {
            ICFSecSecRoleEnablesByNameIdxKey rhs = (ICFSecSecRoleEnablesByNameIdxKey)obj;
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
        int hashCode = pkey.hashCode();
        return( hashCode & 0x7fffffff );
    }

    @Override
    public int compareTo( Object obj ) {
        int cmp;
        if (obj == null) {
            return( 1 );
        }
        else if (obj instanceof ICFSecSecRoleEnables) {
		ICFSecSecRoleEnables rhs = (ICFSecSecRoleEnables)obj;
		if (getPKey() != null) {
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
		else {
			if (rhs.getPKey() != null) {
				return( -1 );
			}
		}
            return( 0 );
        }
        else if (obj instanceof ICFSecSecRoleEnablesHPKey) {
        if (getPKey() != null) {
            return( getPKey().compareTo( obj ));
        }
        else {
            return( -1 );
        }
        }
        else if (obj instanceof ICFSecSecRoleEnablesH) {
		ICFSecSecRoleEnablesH rhs = (ICFSecSecRoleEnablesH)obj;
		if (getPKey() != null) {
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
		else {
			if (rhs.getPKey() != null) {
				return( -1 );
			}
		}
            return( 0 );
        }
        else if (obj instanceof ICFSecSecRoleEnablesByRoleIdxKey ) {
            ICFSecSecRoleEnablesByRoleIdxKey rhs = (ICFSecSecRoleEnablesByRoleIdxKey)obj;
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
            return( 0 );
        }
        else if (obj instanceof ICFSecSecRoleEnablesByNameIdxKey ) {
            ICFSecSecRoleEnablesByNameIdxKey rhs = (ICFSecSecRoleEnablesByNameIdxKey)obj;
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
    public void set( ICFSecSecRoleEnables src ) {
		setSecRoleEnables( src );
    }

	@Override
    public void setSecRoleEnables( ICFSecSecRoleEnables src ) {
		setRequiredSecRoleId( src.getRequiredSecRoleId() );
		setRequiredEnableName( src.getRequiredEnableName() );
		setRequiredRevision( src.getRequiredRevision() );
    }

	@Override
    public void set( ICFSecSecRoleEnablesH src ) {
		setSecRoleEnables( src );
    }

	@Override
    public void setSecRoleEnables( ICFSecSecRoleEnablesH src ) {
		setRequiredSecRoleId( src.getRequiredSecRoleId() );
		setRequiredEnableName( src.getRequiredEnableName() );
		setRequiredRevision( src.getRequiredRevision() );
    }

    public String getXmlAttrFragment() {
        String ret = pkey.getXmlAttrFragment() 
			+ " RequiredRevision=\"" + Integer.toString( getRequiredRevision() ) + "\"";
        return( ret );
    }

    public String toString() {
        String ret = "<CFSecJpaSecRoleEnablesH" + getXmlAttrFragment() + "/>";
        return( ret );
    }
}
