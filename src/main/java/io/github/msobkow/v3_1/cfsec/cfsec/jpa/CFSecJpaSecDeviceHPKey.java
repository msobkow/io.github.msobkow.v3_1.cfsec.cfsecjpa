// Description: Java 25 JPA implementation of a SecDevice history primary key object.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsec.jpa;

import java.io.Serializable;
import java.math.*;
import java.time.*;
import java.util.*;
import jakarta.persistence.*;
import jakarta.transaction.Transactional;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;
import io.github.msobkow.v3_1.cflib.xml.CFLibXmlUtil;
import io.github.msobkow.v3_1.cfsec.cfsec.*;

/**
 *	CFSecJpaSecDeviceHPKey History Primary Key for SecDevice
 *		requiredSecUserId	Required object attribute SecUserId.
 *		requiredDevName	Required object attribute DevName.
 */
public class CFSecJpaSecDeviceHPKey
	implements ICFSecSecDeviceHPKey, Comparable<Object>, Serializable
{
	@Column(name="auditClusterId", nullable=false)
	protected long auditClusterId;

	@Column(name="auditStamp", nullable=false)
	protected LocalDateTime auditStamp;

	@Column(name="auditAction", nullable=false)
	protected short auditActionId;

	@Column(name="requiredRevision", nullable=false)
	protected int requiredRevision;

	@AttributeOverrides({
		@AttributeOverride(name="bytes", column=@Column(name="auditSessionId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH) )
	})
	protected CFLibDbKeyHash256 auditSessionId;

	@AttributeOverrides({
		@AttributeOverride(name="bytes", column = @Column( name="SecUserId", nullable=false, length=CFLibDbKeyHash256.HASH_LENGTH ) )
	})
	protected CFLibDbKeyHash256 requiredSecUserId;
	@Column( name="DevName", nullable=false, length=127 )
	protected String requiredDevName;

	public CFSecJpaSecDeviceHPKey() {
		auditClusterId = ICFSecCluster.ID_INIT_VALUE;
		auditStamp = LocalDateTime.now();
		auditActionId = 0;
		requiredRevision = 1;
		auditSessionId = CFLibDbKeyHash256.nullGet();
		requiredSecUserId = CFLibDbKeyHash256.fromHex( ICFSecSecDevice.SECUSERID_INIT_VALUE.toString() );
		requiredDevName = ICFSecSecDevice.DEVNAME_INIT_VALUE;
	}

	@Override
	public long getAuditClusterId() {
		return( auditClusterId );
	}

	@Override
	public void setAuditClusterId( long value ) {
		auditClusterId = value;
	}

	@Override
	public LocalDateTime getAuditStamp() {
		return( auditStamp );
	}

	@Override
	public void setAuditStamp( LocalDateTime value ) {
		auditStamp = value;
	}

	@Override
	public short getAuditActionId() {
		return( auditActionId );
	}

	@Override
	public void setAuditActionId( short value ) {
		auditActionId = value;
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
	public CFLibDbKeyHash256 getAuditSessionId() {
		return( auditSessionId );
	}

	@Override
	public void setAuditSessionId( CFLibDbKeyHash256 value ) {
		auditSessionId = value;
	}

	@Override
	public CFLibDbKeyHash256 getRequiredSecUserId() {
		return( requiredSecUserId );
	}

	@Override
	public void setRequiredSecUserId( CFLibDbKeyHash256 value ) {
		if( value == null || value.isNull() ) {
			throw new CFLibNullArgumentException( getClass(),
				"setRequiredSecUserId",
				1,
				"value" );
		}
		requiredSecUserId = value;
	}

	@Override
	public String getRequiredDevName() {
		return( requiredDevName );
	}

	@Override
	public void setRequiredDevName( String value ) {
		if( value == null ) {
			throw new CFLibNullArgumentException( getClass(),
				"setRequiredDevName",
				1,
				"value" );
		}
		else if( value.length() > 127 ) {
			throw new CFLibArgumentOverflowException( getClass(),
				"setRequiredDevName",
				1,
				"value.length()",
				value.length(),
				127 );
		}
		requiredDevName = value;
	}

	@Override
	public boolean equals( Object obj ) {
		if (obj == null) {
			return( false );
		}
		else if (obj instanceof ICFSecSecDevice) {
			ICFSecSecDevice rhs = (ICFSecSecDevice)obj;
			if( getRequiredSecUserId() != null && !getRequiredSecUserId().isNull() ) {
				if( rhs.getRequiredSecUserId() != null && !rhs.getRequiredSecUserId().isNull() ) {
					if( ! getRequiredSecUserId().equals( rhs.getRequiredSecUserId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecUserId() != null && !getRequiredSecUserId().isNull()) {
					return( false );
				}
			}
			if( getRequiredDevName() != null ) {
				if( rhs.getRequiredDevName() != null ) {
					if( ! getRequiredDevName().equals( rhs.getRequiredDevName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredDevName() != null ) {
					return( false );
				}
			}
			return( true );
		}
		else if (obj instanceof ICFSecSecDeviceHPKey) {
			ICFSecSecDeviceHPKey rhs = (ICFSecSecDeviceHPKey)obj;
			if (getAuditClusterId() != rhs.getAuditClusterId()) {
				return( false );
			}
			if (getAuditStamp() != null) {
				if (rhs.getAuditStamp() != null) {
					if ( ! getAuditStamp().equals(rhs.getAuditStamp())) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else if (rhs.getAuditStamp() != null) {
				return( false );
			}
			if( getAuditActionId() != rhs.getAuditActionId() ) {
				return( false );
			}
			if( getRequiredRevision() != rhs.getRequiredRevision() ) {
				return( false );
			}
			if (getAuditSessionId() != null && !getAuditSessionId().isNull() ) {
				if (rhs.getAuditSessionId() != null && !rhs.getAuditSessionId().isNull() ) {
					if ( ! getAuditSessionId().equals(rhs.getAuditSessionId())) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else if (rhs.getAuditSessionId() != null && !rhs.getAuditSessionId().isNull() ) {
				return( false );
			}
			if( getRequiredSecUserId() != null && !getRequiredSecUserId().isNull() ) {
				if( rhs.getRequiredSecUserId() != null && !rhs.getRequiredSecUserId().isNull() ) {
					if( ! getRequiredSecUserId().equals( rhs.getRequiredSecUserId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecUserId() != null && !getRequiredSecUserId().isNull()) {
					return( false );
				}
			}
			if( getRequiredDevName() != null ) {
				if( rhs.getRequiredDevName() != null ) {
					if( ! getRequiredDevName().equals( rhs.getRequiredDevName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredDevName() != null ) {
					return( false );
				}
			}
			return( true );
		}
		else if (obj instanceof ICFSecSecDeviceH) {
			ICFSecSecDeviceH rhs = (ICFSecSecDeviceH)obj;
			if (getAuditClusterId() != rhs.getAuditClusterId()) {
				return( false );
			}
			if (getAuditStamp() != null) {
				if (rhs.getAuditStamp() != null) {
					if ( ! getAuditStamp().equals(rhs.getAuditStamp())) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else if (rhs.getAuditStamp() != null) {
				return( false );
			}
			if( getAuditActionId() != rhs.getAuditActionId() ) {
				return( false );
			}
			if( getRequiredRevision() != rhs.getRequiredRevision() ) {
				return( false );
			}
			if (getAuditSessionId() != null && !getAuditSessionId().isNull() ) {
				if (rhs.getAuditSessionId() != null && !rhs.getAuditSessionId().isNull() ) {
					if ( ! getAuditSessionId().equals(rhs.getAuditSessionId())) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else if (rhs.getAuditSessionId() != null && !rhs.getAuditSessionId().isNull() ) {
				return( false );
			}
			if( getRequiredSecUserId() != null && !getRequiredSecUserId().isNull() ) {
				if( rhs.getRequiredSecUserId() != null && !rhs.getRequiredSecUserId().isNull() ) {
					if( ! getRequiredSecUserId().equals( rhs.getRequiredSecUserId() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredSecUserId() != null && !getRequiredSecUserId().isNull()) {
					return( false );
				}
			}
			if( getRequiredDevName() != null ) {
				if( rhs.getRequiredDevName() != null ) {
					if( ! getRequiredDevName().equals( rhs.getRequiredDevName() ) ) {
						return( false );
					}
				}
				else {
					return( false );
				}
			}
			else {
				if( rhs.getRequiredDevName() != null ) {
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
		hashCode = hashCode + (int)( auditClusterId ) & 0x7fffffff;
		if( auditStamp != null ) {
			hashCode = hashCode + auditStamp.hashCode();
		}
		hashCode = hashCode + auditActionId;
		hashCode = hashCode + requiredRevision;
		if( auditSessionId != null ) {
			hashCode = hashCode + auditSessionId.hashCode();
		}
		hashCode = hashCode + getRequiredSecUserId().hashCode();
		if( getRequiredDevName() != null ) {
			hashCode = hashCode + getRequiredDevName().hashCode();
		}
		return( hashCode & 0x7fffffff );
	}

	@Override
	public int compareTo( Object obj ) {
		int cmp;
		if (obj == null) {
			return( 1 );
		}
		else if (obj instanceof ICFSecSecDevice) {
			ICFSecSecDevice rhs = (ICFSecSecDevice)obj;
			if (getRequiredSecUserId() != null) {
				if (rhs.getRequiredSecUserId() != null) {
					cmp = getRequiredSecUserId().compareTo( rhs.getRequiredSecUserId() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecUserId() != null) {
				return( -1 );
			}
			if (getRequiredDevName() != null) {
				if (rhs.getRequiredDevName() != null) {
					cmp = getRequiredDevName().compareTo( rhs.getRequiredDevName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredDevName() != null) {
				return( -1 );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecSecDeviceHPKey) {
			ICFSecSecDeviceHPKey rhs = (ICFSecSecDeviceHPKey)obj;
			if (getAuditClusterId() < rhs.getAuditClusterId()) {
				return( -1 );
			}
			else if (getAuditClusterId() > rhs.getAuditClusterId()) {
				return( 1 );
			}
			if( getAuditStamp() == null ) {
				if( rhs.getAuditStamp() != null ) {
					return( -1 );
				}
			}
			else if( rhs.getAuditStamp() == null ) {
				return( 1 );
			}
			else {
				cmp = getAuditStamp().compareTo( rhs.getAuditStamp() );
				if( cmp != 0 ) {
					return( cmp );
				}
			}
			if( getAuditActionId() < rhs.getAuditActionId() ) {
				return( -1 );
			}
			else if( getAuditActionId() > rhs.getAuditActionId() ) {
				return( 1 );
			}
			if( getRequiredRevision() < rhs.getRequiredRevision() ) {
				return( -1 );
			}
			else if( getRequiredRevision() > rhs.getRequiredRevision() ) {
				return( 1 );
			}
			if( getAuditSessionId() == null ) {
				if( rhs.getAuditSessionId() != null ) {
					return( -1 );
				}
			}
			else if( rhs.getAuditSessionId() == null ) {
				return( 1 );
			}
			else {
				cmp = getAuditSessionId().compareTo( rhs.getAuditSessionId() );
				if( cmp != 0 ) {
					return( cmp );
				}
			}
			if (getRequiredSecUserId() != null) {
				if (rhs.getRequiredSecUserId() != null) {
					cmp = getRequiredSecUserId().compareTo( rhs.getRequiredSecUserId() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecUserId() != null) {
				return( -1 );
			}
			if (getRequiredDevName() != null) {
				if (rhs.getRequiredDevName() != null) {
					cmp = getRequiredDevName().compareTo( rhs.getRequiredDevName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredDevName() != null) {
				return( -1 );
			}
			return( 0 );
		}
		else if (obj instanceof ICFSecSecDeviceH) {
			ICFSecSecDeviceH rhs = (ICFSecSecDeviceH)obj;
			if (getAuditClusterId() < rhs.getAuditClusterId()) {
				return( -1 );
			}
			else if (getAuditClusterId() > rhs.getAuditClusterId()) {
				return( 1 );
			}
			if( getAuditStamp() == null ) {
				if( rhs.getAuditStamp() != null ) {
					return( -1 );
				}
			}
			else if( rhs.getAuditStamp() == null ) {
				return( 1 );
			}
			else {
				cmp = getAuditStamp().compareTo( rhs.getAuditStamp() );
				if( cmp != 0 ) {
					return( cmp );
				}
			}
			if( getAuditActionId() < rhs.getAuditActionId() ) {
				return( -1 );
			}
			else if( getAuditActionId() > rhs.getAuditActionId() ) {
				return( 1 );
			}
			if( getRequiredRevision() < rhs.getRequiredRevision() ) {
				return( -1 );
			}
			else if( getRequiredRevision() > rhs.getRequiredRevision() ) {
				return( 1 );
			}
			if( getAuditSessionId() == null ) {
				if( rhs.getAuditSessionId() != null ) {
					return( -1 );
				}
			}
			else if( rhs.getAuditSessionId() == null ) {
				return( 1 );
			}
			else {
				cmp = getAuditSessionId().compareTo( rhs.getAuditSessionId() );
				if( cmp != 0 ) {
					return( cmp );
				}
			}
			if (getRequiredSecUserId() != null) {
				if (rhs.getRequiredSecUserId() != null) {
					cmp = getRequiredSecUserId().compareTo( rhs.getRequiredSecUserId() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredSecUserId() != null) {
				return( -1 );
			}
			if (getRequiredDevName() != null) {
				if (rhs.getRequiredDevName() != null) {
					cmp = getRequiredDevName().compareTo( rhs.getRequiredDevName() );
					if( cmp != 0 ) {
						return( cmp );
					}
				}
				else {
					return( 1 );
				}
			}
			else if (rhs.getRequiredDevName() != null) {
				return( -1 );
			}
			return( 0 );
		}
		else {
			throw new CFLibUnsupportedClassException( getClass(),
				"compareTo",
				"obj",
				obj,
				"ICFSecSecDevicePKey, ICFSecSecDevice, ICFSecSecDeviceHPKey, ICFSecSecDeviceH" );
		}
	}

	@Override
	public String getXmlAttrFragment() {
		String ret = " auditClusterId=\"" + auditClusterId + "\""
			+ " auditStamp=\"" + (auditStamp != null ? CFLibXmlUtil.formatTimestamp(auditStamp) : "null") + "\""
			+ " auditAction=\"" + auditActionId + "\""
			+ " requiredRevision=\"" + requiredRevision + "\""
			+ " auditSessionId=\"" + (getAuditSessionId() != null ? getAuditSessionId().toString() : "null") + "\""
			+ " RequiredSecUserId=" + "\"" + getRequiredSecUserId().toString() + "\""
			+ " RequiredDevName=" + "\"" + StringEscapeUtils.escapeXml11( getRequiredDevName() ) + "\"";
		return( ret );
	}

	@Override
	public String toString() {
		String ret = "<CFSecJpaSecDeviceHPKey" + getXmlAttrFragment() + "/>";
		return( ret );
	}
}
